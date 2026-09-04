package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Ayoshiss/sentinel-subnet/gateway/billing"
	"github.com/Ayoshiss/sentinel-subnet/gateway/ratelimit"
	"github.com/Ayoshiss/sentinel-subnet/gateway/risk"
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
	Tier       string        `json:"tier"`          // "free" | "keyed"
	Upgrade    string        `json:"upgrade,omitempty"`
	Disclaimer string        `json:"disclaimer"`
}

// Free keyless tier: heuristics-only (no LLM cost), rate-limited by IP. Lets the
// scan ship inside agent frameworks with zero friction; a BHAIRAB_API_KEY unlocks
// the AI-reasoned verdict.
const freeScanRPM = 20

// scanAITimeout caps how long an ambiguous (non-severe, keyed) scan waits on the
// model before falling back to the deterministic verdict. Severe/honeypot cases
// never reach the model, they return instantly.
const scanAITimeout = 9 * time.Second

const upgradeHint = "Set BHAIRAB_API_KEY for AI-reasoned verdicts and higher limits, free at https://tao-gateway.vercel.app"

// clientIP extracts the caller's IP for free-tier rate limiting (Fly sets
// Fly-Client-IP / X-Forwarded-For in front of the app).
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("Fly-Client-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
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

// scanCaller derives a stable identifier for "distinct callers" telemetry:
// the IP for free scans, the key id for prepaid, the wallet for x402.
func scanCaller(c *caller, r *http.Request, freeTier bool) string {
	switch {
	case freeTier:
		return "ip:" + clientIP(r)
	case c.method == "x402":
		return "wallet:" + c.payer
	default:
		return "key:" + c.apiKeyID
	}
}

func handleRiskScan(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Tier check: a Bearer key or x402 payment gets the AI verdict; no credentials
	// falls through to the free keyless tier (heuristics-only, IP rate-limited).
	hasKey := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
	hasPay := r.Header.Get("X-Payment") != ""
	freeTier := !hasKey && !hasPay

	var c *caller
	if freeTier {
		key := "free-scan:" + clientIP(r)
		allowed, remaining, resetAt := ratelimit.Allow(key, freeScanRPM)
		if !allowed {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(resetAt).Seconds())))
			http.Error(w, `{"error":"free-tier rate limit exceeded, set BHAIRAB_API_KEY for higher limits","type":"rate_limit_error"}`, http.StatusTooManyRequests)
			return
		}
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c = &caller{method: "free", rlKey: key, quotaRPM: freeScanRPM}
	} else {
		var ok bool
		c, ok = resolveCaller(w, r, riskResource)
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
				http.Error(w, `{"error":"insufficient balance, top up at https://tao-gateway.vercel.app/dashboard","type":"billing_error"}`, http.StatusPaymentRequired)
				return
			}
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

	// 1) LIVE signals, the moat. v1 market axis on Solana via DexScreener.
	signals, sigErr := risk.Gather(req.Chain, req.Token)
	if sigErr != nil {
		log.Printf("risk: signal gather error for %s/%s: %v", req.Chain, req.Token, sigErr)
	}

	var (
		verdict       scanVerdict
		servedModel   = "heuristic"
		source        = "deterministic"
		promptTok     int
		completionTok int
	)

	switch {
	case freeTier:
		// Heuristics only: zero LLM cost. The deterministic floor is the
		// high-signal layer; the AI narrative is the keyed upsell.
		verdict = deterministicVerdict(signals)

	case signals.Severe():
		// Danger is unambiguous (honeypot, crash, near-zero liquidity): return
		// the verdict INSTANTLY from the deterministic floor. Never make the user
		// wait on the model for a STOP, and never spend an inference on an obvious
		// trap. This is what makes the scary verdict fast.
		verdict = deterministicVerdict(signals)
		source = "deterministic-severe"

	case signals.ClearlySafe():
		// Obviously-safe blue chip, also instant. The AI adds nothing here.
		verdict = deterministicVerdict(signals)
		source = "deterministic-clear"

	default:
		// Only the genuinely ambiguous tokens reach the AI, where reasoning earns
		// its latency. Capped + falls back to the deterministic verdict on timeout.
		verdict, servedModel, promptTok, completionTok, source = synthesizeVerdict(req, signals)
		bill(c, "SN64-Chutes", "risk-scan", servedModel, promptTok, completionTok, int(time.Since(start).Milliseconds()), "ok")
	}

	latency := int(time.Since(start).Milliseconds())
	tier := map[bool]string{true: "free", false: "keyed"}[freeTier]

	// Persist the engagement signal (async, never blocks the response). IP is
	// recorded separately so distinct visitors are countable even when the public
	// page authenticates everyone with one shared demo key.
	recordScan(tier, verdict.Verdict, source, scanCaller(c, r, freeTier), req.Token, clientIP(r))

	resp := scanResponse{
		scanVerdict: verdict,
		Signals:     signals,
		Model:       servedModel,
		LatencyMs:   latency,
		Source:      source,
		Tier:        tier,
		Disclaimer:  scanDisclaimer,
	}
	if freeTier {
		resp.Upgrade = upgradeHint
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Latency-Ms", fmt.Sprintf("%d", latency))
	json.NewEncoder(w).Encode(resp)
}

// synthesizeVerdict asks the LLM to judge the transaction given the signals, and
// falls back to a deterministic verdict if the model is unreachable or unparseable
//, so the guardian never silently fails open.
func synthesizeVerdict(req scanRequest, s *risk.Signals) (v scanVerdict, model string, promptTok, completionTok int, source string) {
	ctx, _ := json.Marshal(map[string]any{
		"intent":  req,
		"signals": s,
	})
	chatBody, _ := json.Marshal(map[string]any{
		"model":       "auto",
		"temperature": 0,
		"max_tokens":  220, // a verdict is short: bound generation time
		"messages": []map[string]string{
			{"role": "system", "content": scanSystemPrompt},
			{"role": "user", "content": "Assess this transaction:\n" + string(ctx)},
		},
	})

	// Hard latency cap: a guardian slower than the trade is theater. If the model
	// doesn't answer in time, fall back to the (honeypot-aware) deterministic floor.
	client := &http.Client{Timeout: scanAITimeout}
	httpResp, err := client.Post(sidecarURL+"/query", "application/json", bytes.NewReader(chatBody))
	if err != nil {
		return deterministicVerdict(s), "deterministic", 0, 0, "deterministic"
	}
	resp := httpResp
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
			Summary:    "No market data for this token, unknown or illiquid; proceed only if you know it.",
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
