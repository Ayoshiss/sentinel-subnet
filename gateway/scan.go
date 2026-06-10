package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/taogateway/gateway/billing"
	"github.com/taogateway/gateway/ratelimit"
	"github.com/taogateway/gateway/risk"
)

// riskResource scopes x402 payments to the scan endpoint.
const riskResource = "/v1/risk/scan"

// scanRequest is the transaction the caller is about to make.
type scanRequest struct {
	Chain     string  `json:"chain"`     // e.g. "solana"
	Token     string  `json:"token"`     // mint / contract address being acquired or touched
	Action    string  `json:"action"`    // buy|sell|swap|transfer|approve
	AmountUSD float64 `json:"amountUsd"` // optional, for context
	Venue     string  `json:"venue"`     // optional DEX/pool label
}

// scanVerdict is the AI's judgement (also producible deterministically).
type scanVerdict struct {
	Verdict    string   `json:"verdict"`    // proceed|caution|stop
	Confidence float64  `json:"confidence"` // 0..1
	Summary    string   `json:"summary"`
	Reasons    []string `json:"reasons"`
}

// scanResponse is the full payload returned to the caller.
type scanResponse struct {
	scanVerdict
	Signals    *risk.Signals `json:"signals"`
	Model      string        `json:"model"`
	LatencyMs  int           `json:"latencyMs"`
	Source     string        `json:"verdictSource"` // "ai" | "deterministic"
	Disclaimer string        `json:"disclaimer"`
}

const scanDisclaimer = "Risk insight, not financial advice. Bhairab scans available signals; absence of a flag is not a guarantee of safety."

const scanSystemPrompt = `You are Bhairab, a blockchain transaction risk guardian. You receive a user's intended on-chain transaction and LIVE market signals gathered moments ago. Judge the risk of proceeding RIGHT NOW.

Rules:
- Reason ONLY from the provided signals and widely-known facts. Never invent data, prices, or events.
- Be conservative. If signals show danger or are missing, lean toward "caution" or "stop".
- "stop" = severe risk (crashing, near-zero liquidity, likely scam/manipulation, brand-new unbacked token).
- "caution" = elevated or uncertain risk (thin liquidity, no market data, high volatility).
- "proceed" = signals look healthy and the action is reasonable.
- Cite the specific signal behind each reason.

Respond with STRICT JSON ONLY (no markdown, no prose) matching exactly:
{"verdict":"proceed|caution|stop","confidence":0.0,"summary":"one sentence","reasons":["...","..."]}`

func handleRiskScan(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	c, ok := resolveCaller(w, r, riskResource)
	if !ok {
		return
	}

	allowed, remaining, resetAt := ratelimit.Allow(c.rlKey, c.quotaRPM)
	if !allowed {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(resetAt).Seconds())))
		http.Error(w, `{"error":"rate limit exceeded","type":"rate_limit_error"}`, http.StatusTooManyRequests)
		return
	}
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

	if c.method == "prepaid" {
		if bal, err := billing.GetBalance(r.Context(), c.customerID); err == nil && bal <= 0 {
			http.Error(w, `{"error":"insufficient balance — top up at https://tao-gateway.vercel.app/dashboard","type":"billing_error"}`, http.StatusPaymentRequired)
			return
		}
	}

	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req scanRequest
	if err := json.Unmarshal(raw, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		http.Error(w, `{"error":"bad request: {chain, token, action} required","type":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if req.Chain == "" {
		req.Chain = "solana"
	}

	// 1) LIVE signals — the moat. v1 market axis on Solana via DexScreener.
	signals, sigErr := risk.Gather(req.Chain, req.Token)
	if sigErr != nil {
		log.Printf("risk: signal gather error for %s/%s: %v", req.Chain, req.Token, sigErr)
	}

	// 2) AI synthesis over the signals (reuses the inference plumbing).
	verdict, servedModel, promptTok, completionTok, source := synthesizeVerdict(req, signals)

	// 3) Severe deterministic facts override an over-optimistic model.
	if signals.Severe() && verdict.Verdict == "proceed" {
		verdict.Verdict = "stop"
		verdict.Confidence = 0.9
		verdict.Reasons = append([]string{"deterministic override: signals indicate severe risk"}, verdict.Reasons...)
		source = "deterministic-override"
	}

	latency := int(time.Since(start).Milliseconds())
	bill(c, "SN64-Chutes", "risk-scan", servedModel, promptTok, completionTok, latency, "ok")

	resp := scanResponse{
		scanVerdict: verdict,
		Signals:     signals,
		Model:       servedModel,
		LatencyMs:   latency,
		Source:      source,
		Disclaimer:  scanDisclaimer,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Latency-Ms", fmt.Sprintf("%d", latency))
	json.NewEncoder(w).Encode(resp)
}

// synthesizeVerdict asks the LLM to judge the transaction given the signals, and
// falls back to a deterministic verdict if the model is unreachable or unparseable
// — so the guardian never silently fails open.
func synthesizeVerdict(req scanRequest, s *risk.Signals) (v scanVerdict, model string, promptTok, completionTok int, source string) {
	ctx, _ := json.Marshal(map[string]any{
		"intent":  req,
		"signals": s,
	})
	chatBody, _ := json.Marshal(map[string]any{
		"model":       "auto",
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "system", "content": scanSystemPrompt},
			{"role": "user", "content": "Assess this transaction:\n" + string(ctx)},
		},
	})

	resp, err := callSidecar("/query", chatBody)
	if err != nil {
		return deterministicVerdict(s), "deterministic", 0, 0, "deterministic"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var oa struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &oa) != nil || len(oa.Choices) == 0 {
		return deterministicVerdict(s), "deterministic", 0, 0, "deterministic"
	}

	parsed, ok := parseVerdictJSON(oa.Choices[0].Message.Content)
	if !ok || parsed.Verdict == "" {
		return deterministicVerdict(s), oa.Model, oa.Usage.PromptTokens, oa.Usage.CompletionTokens, "deterministic"
	}
	parsed.Verdict = normalizeVerdict(parsed.Verdict)
	return parsed, oa.Model, oa.Usage.PromptTokens, oa.Usage.CompletionTokens, "ai"
}

// parseVerdictJSON tolerantly extracts the JSON object from a model response that
// may be wrapped in prose or code fences.
func parseVerdictJSON(content string) (scanVerdict, bool) {
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end <= start {
		return scanVerdict{}, false
	}
	var v scanVerdict
	if json.Unmarshal([]byte(content[start:end+1]), &v) != nil {
		return scanVerdict{}, false
	}
	return v, true
}

func normalizeVerdict(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "proceed", "go", "safe", "ok", "allow":
		return "proceed"
	case "stop", "block", "abort", "danger", "deny":
		return "stop"
	default:
		return "caution"
	}
}

// deterministicVerdict is the trustworthy floor: a verdict from heuristics alone,
// used whenever the LLM can't be reached or trusted.
func deterministicVerdict(s *risk.Signals) scanVerdict {
	switch {
	case s.Severe():
		return scanVerdict{
			Verdict:    "stop",
			Confidence: 0.85,
			Summary:    "Live signals indicate severe risk; do not proceed right now.",
			Reasons:    s.Heuristics,
		}
	case !s.Found:
		return scanVerdict{
			Verdict:    "caution",
			Confidence: 0.6,
			Summary:    "No market data for this token — unknown or illiquid; proceed only if you know it.",
			Reasons:    s.Heuristics,
		}
	case len(s.Heuristics) == 1 && s.Heuristics[0] == "no_red_flags_in_market_data":
		return scanVerdict{
			Verdict:    "proceed",
			Confidence: 0.7,
			Summary:    "No red flags in available market signals.",
			Reasons:    s.Heuristics,
		}
	default:
		return scanVerdict{
			Verdict:    "caution",
			Confidence: 0.65,
			Summary:    "Elevated risk in market signals; review before proceeding.",
			Reasons:    s.Heuristics,
		}
	}
}
