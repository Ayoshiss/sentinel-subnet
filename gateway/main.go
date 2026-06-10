package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/taogateway/gateway/auth"
	"github.com/taogateway/gateway/billing"
	"github.com/taogateway/gateway/db"
	"github.com/taogateway/gateway/keys"
	"github.com/taogateway/gateway/pricing"
	"github.com/taogateway/gateway/ratelimit"
	"github.com/taogateway/gateway/x402"
	"sync"
)

var sidecarURL = getEnv("SIDECAR_URL", "http://localhost:8001")

// ctxKey for passing API key data through request context
type ctxKey string

const ctxAPIKey ctxKey = "apikey"

func main() {
	ctx := context.Background()

	if err := db.Connect(ctx); err != nil {
		log.Fatalf("database: %v", err)
	}
	log.Println("Connected to Postgres")

	// Clean up stale rate limit windows every minute
	go func() {
		for range time.Tick(time.Minute) {
			ratelimit.Cleanup()
		}
	}()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(corsMiddleware)

	r.Get("/health", handleHealth)
	// Accepts EITHER a prepaid API key OR an x402 crypto payment (no middleware;
	// resolveCaller handles both inside the handler).
	r.Post("/v1/chat/completions", handleChatCompletions)

	// Pre-transaction risk scan — AI guardian that reads LIVE signals and returns
	// a verdict before money moves. Same prepaid-or-x402 auth (agents pay to scan).
	r.Post("/v1/risk/scan", handleRiskScan)

	// Auth routes — magic link
	r.Post("/auth/request", handleAuthRequest)
	r.Get("/auth/verify", handleAuthVerify)

	// Dashboard API — session required
	r.With(sessionMiddleware).Get("/v1/usage", handleUsage)
	r.With(sessionMiddleware).Get("/v1/keys", handleListKeys)
	r.With(sessionMiddleware).Delete("/v1/keys/{id}", handleRevokeKey)

	// Account
	r.With(sessionMiddleware).Get("/v1/account", handleGetAccount)
	r.With(sessionMiddleware).Patch("/v1/account", handleUpdateAccount)

	// Billing routes
	r.With(sessionMiddleware).Post("/v1/billing/checkout", handleCreateCheckout)
	r.With(sessionMiddleware).Get("/v1/billing/balance", handleGetBalance)
	r.With(sessionMiddleware).Get("/v1/billing/history", handleBillingHistory)
	r.With(sessionMiddleware).Post("/v1/billing/portal", handleBillingPortal)
	r.Post("/v1/billing/webhook", handleStripeWebhook)

	// Admin routes — protected by ADMIN_SECRET header
	r.With(adminMiddleware).Post("/admin/customers", handleCreateCustomer)
	r.With(adminMiddleware).Post("/admin/keys", handleCreateKey)
	r.With(adminMiddleware).Get("/admin/margin", handleMargin)

	addr := ":" + getEnv("PORT", "8080")
	log.Printf("TAO Gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

// ── Health ────────────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "subnet": "SN64-Chutes"})
}

// ── Caller: prepaid API key OR x402 crypto payment ────────────────────────────

const x402Resource = "/v1/chat/completions"

// caller is whoever authorized this request — a prepaid key holder or an x402 payer.
type caller struct {
	method     string // "prepaid" | "x402"
	apiKeyID   string // prepaid only
	customerID string // prepaid only
	quotaRPM   int
	rlKey      string // rate-limit bucket
	payer      string // x402 payer pubkey (logging)
}

func x402PriceMicro() int64 {
	if v := os.Getenv("X402_PRICE_MICRO"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 1000 // 0.001 USDC default (matches Lattice)
}

// In-memory single-use nonce store with TTL (v1 — multi-instance needs Redis).
var (
	nonceMu    sync.Mutex
	nonceStore = map[string]time.Time{}
)

func issueNonce(n string) {
	nonceMu.Lock()
	nonceStore[n] = time.Now().Add(5 * time.Minute)
	nonceMu.Unlock()
}

func consumeNonce(n string) bool {
	nonceMu.Lock()
	defer nonceMu.Unlock()
	exp, ok := nonceStore[n]
	delete(nonceStore, n) // single-use regardless
	return ok && time.Now().Before(exp)
}

// write402 issues an x402 Payment Required challenge for a specific resource.
func write402(w http.ResponseWriter, resource string) {
	header, nonce := x402.Build402(resource, x402PriceMicro())
	issueNonce(nonce)
	w.Header().Set("X-Payment-Required", header)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "payment required",
		"type":  "x402",
		"hint":  "pay via x402 (Solana USDC) and retry with X-PAYMENT, or use a Bearer API key",
	})
}

// resolveCaller authorizes the request for a given x402 resource (the endpoint the
// payment must be scoped to). Returns (caller,true) or writes 401/402.
func resolveCaller(w http.ResponseWriter, r *http.Request, resource string) (*caller, bool) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		k, err := keys.Lookup(r.Context(), strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return nil, false
		}
		if k == nil {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return nil, false
		}
		return &caller{method: "prepaid", apiKeyID: k.ID, customerID: k.CustomerID, quotaRPM: k.QuotaRPM, rlKey: k.ID}, true
	}
	if pay := r.Header.Get("X-Payment"); pay != "" {
		proof, ok := x402.ParseProof(pay)
		if !ok || !x402.Verify(proof, resource, "", x402PriceMicro()) || !consumeNonce(proof.Nonce) {
			write402(w, resource)
			return nil, false
		}
		log.Printf("x402 payment accepted: payer=%s amount=%s resource=%s", proof.Pubkey, proof.Amount, resource)
		return &caller{method: "x402", quotaRPM: 60, rlKey: "x402:" + proof.Pubkey, payer: proof.Pubkey}, true
	}
	// No key, no payment → invite payment.
	write402(w, resource)
	return nil, false
}

// bill records the charge. Prepaid → deduct balance + usage event. x402 → log
// (a proper x402 ledger is a fast-follow).
func bill(c *caller, subnet, reqModel, servedModel string, prompt, completion, latency int, status string) {
	costUSD := pricing.Retail(prompt, completion)
	wholesaleUSD := pricing.Wholesale(servedModel, prompt, completion)
	if c.method == "prepaid" {
		go billing.DeductBalance(context.Background(), c.customerID, costUSD)
		go keys.RecordUsage(c.apiKeyID, c.customerID, subnet, reqModel, status,
			prompt, completion, latency, costUSD, wholesaleUSD, servedModel)
		return
	}
	log.Printf("x402 usage: payer=%s served=%s status=%s tokens=%d/%d retail=$%.6f wholesale=$%.6f",
		c.payer, servedModel, status, prompt, completion, costUSD, wholesaleUSD)
}

// ── Chat completions ──────────────────────────────────────────────────────────

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	c, ok := resolveCaller(w, r, x402Resource)
	if !ok {
		return
	}

	// ── Rate limiting ──────────────────────────────────────────────────────────
	allowed, remaining, resetAt := ratelimit.Allow(c.rlKey, c.quotaRPM)
	if !allowed {
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", c.quotaRPM))
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(resetAt).Seconds())))
		http.Error(w, `{"error":"rate limit exceeded","type":"rate_limit_error"}`, http.StatusTooManyRequests)
		return
	}
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

	// ── Balance check (prepaid only; x402 already paid for this call) ────────────
	if c.method == "prepaid" {
		balance, err := billing.GetBalance(r.Context(), c.customerID)
		if err == nil && balance <= 0 {
			http.Error(w, `{"error":"insufficient balance — top up at https://tao-gateway.vercel.app/dashboard","type":"billing_error"}`, http.StatusPaymentRequired)
			return
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	// Parse request to extract model + stream flag for billing
	var req struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	json.Unmarshal(body, &req)

	// ── Streaming path (SSE) ─────────────────────────────────────────────────────
	if req.Stream {
		handleStreaming(w, c, body, req.Model, start)
		return
	}

	resp, err := callSidecar("/query", body)
	if err != nil {
		log.Printf("sidecar error: %v", err)
		bill(c, "SN64-Chutes", req.Model, "", 0, 0, int(time.Since(start).Milliseconds()), "error")
		http.Error(w, `{"error":"subnet unavailable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	latency := int(time.Since(start).Milliseconds())

	// Parse response for token counts AND the model that actually served it
	// (router/fallback/backstop may differ from what the customer requested).
	var openAIResp struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	json.Unmarshal(respBody, &openAIResp)
	promptTok := openAIResp.Usage.PromptTokens
	completionTok := openAIResp.Usage.CompletionTokens

	subnet := resp.Header.Get("X-Routed-Subnet")
	if subnet == "" {
		subnet = "SN64-Chutes"
	}

	// Bill the caller (prepaid → deduct + record; x402 → log).
	bill(c, subnet, req.Model, openAIResp.Model, promptTok, completionTok, latency, "ok")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Routed-Subnet", subnet)
	w.Header().Set("X-Latency-Ms", fmt.Sprintf("%d", latency))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ── Streaming (SSE) ───────────────────────────────────────────────────────────

func handleStreaming(w http.ResponseWriter, c *caller, body []byte, model string, start time.Time) {
	resp, err := callSidecar("/query", body)
	if err != nil {
		log.Printf("sidecar stream error: %v", err)
		bill(c, "SN64-Chutes", model, "", 0, 0, int(time.Since(start).Milliseconds()), "error")
		http.Error(w, `{"error":"subnet unavailable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// If the sidecar failed before streaming, forward the error
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(errBody)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
		return
	}

	subnet := resp.Header.Get("X-Routed-Subnet")
	if subnet == "" {
		subnet = "SN64-Chutes"
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Routed-Subnet", subnet)
	w.WriteHeader(http.StatusOK)

	// Scan the SSE stream line by line: forward each line to the client
	// immediately, and capture usage from the final chunk for billing.
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024) // up to 4 MB per line

	var promptTok, completionTok int
	var servedModel string
	for scanner.Scan() {
		line := scanner.Bytes()

		// Forward the line to the client and flush so it streams in real time
		w.Write(line)
		w.Write([]byte("\n"))
		flusher.Flush()

		// Capture usage + served model from data chunks (include_usage puts the
		// final usage in the last chunk; model is on every chunk)
		if bytes.HasPrefix(line, []byte("data: ")) {
			payload := bytes.TrimSpace(line[6:])
			if !bytes.Equal(payload, []byte("[DONE]")) {
				var chunk struct {
					Model string `json:"model"`
					Usage *struct {
						PromptTokens     int `json:"prompt_tokens"`
						CompletionTokens int `json:"completion_tokens"`
					} `json:"usage"`
				}
				if json.Unmarshal(payload, &chunk) == nil {
					if chunk.Model != "" {
						servedModel = chunk.Model
					}
					if chunk.Usage != nil {
						promptTok = chunk.Usage.PromptTokens
						completionTok = chunk.Usage.CompletionTokens
					}
				}
			}
		}
	}

	latency := int(time.Since(start).Milliseconds())
	bill(c, subnet, model, servedModel, promptTok, completionTok, latency, "ok")
}

// ── Admin: create customer ────────────────────────────────────────────────────

func handleCreateCustomer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, `{"error":"email required"}`, http.StatusBadRequest)
		return
	}

	var id string
	err := db.Pool.QueryRow(r.Context(), `
		INSERT INTO customers (email, name) VALUES ($1, $2)
		RETURNING id
	`, body.Email, body.Name).Scan(&id)
	if err != nil {
		http.Error(w, `{"error":"could not create customer"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"customer_id": id})
}

// ── Admin: create API key ─────────────────────────────────────────────────────

func handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CustomerID string `json:"customer_id"`
		Name       string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CustomerID == "" {
		http.Error(w, `{"error":"customer_id required"}`, http.StatusBadRequest)
		return
	}

	rawKey, err := keys.Generate(r.Context(), body.CustomerID, body.Name)
	if err != nil {
		log.Printf("key generate: %v", err)
		http.Error(w, `{"error":"could not generate key"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"key":  rawKey,
		"note": "Store this key — it will not be shown again.",
	})
}

// handleMargin reports retail vs wholesale (COGS) per served model over the
// last N days — the hard data that proves the Tier-1 router is preserving margin
// by down-routing simple prompts to cheaper models. ?days=7 (default).
func handleMargin(w http.ResponseWriter, r *http.Request) {
	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}

	rows, err := db.Pool.Query(r.Context(), `
		SELECT
			COALESCE(served_model, '(unknown)') AS model,
			COUNT(*)                            AS requests,
			COALESCE(SUM(prompt_tokens + completion_tokens), 0) AS tokens,
			COALESCE(SUM(cost_usd), 0)          AS retail,
			COALESCE(SUM(wholesale_cost_usd), 0) AS wholesale
		FROM usage_events
		WHERE status = 'ok' AND ts >= NOW() - make_interval(days => $1)
		GROUP BY served_model
		ORDER BY retail DESC
	`, days)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Row struct {
		Model     string  `json:"model"`
		Requests  int64   `json:"requests"`
		Tokens    int64   `json:"tokens"`
		Retail    float64 `json:"retail_usd"`
		Wholesale float64 `json:"wholesale_usd"`
		Margin    float64 `json:"margin_usd"`
		MarginPct float64 `json:"margin_pct"`
	}
	var breakdown []Row
	var totRetail, totWholesale float64
	var totReq int64
	for rows.Next() {
		var x Row
		rows.Scan(&x.Model, &x.Requests, &x.Tokens, &x.Retail, &x.Wholesale)
		x.Margin = x.Retail - x.Wholesale
		if x.Retail > 0 {
			x.MarginPct = x.Margin / x.Retail * 100
		}
		totRetail += x.Retail
		totWholesale += x.Wholesale
		totReq += x.Requests
		breakdown = append(breakdown, x)
	}
	if breakdown == nil {
		breakdown = []Row{}
	}

	totMargin := totRetail - totWholesale
	var totMarginPct float64
	if totRetail > 0 {
		totMarginPct = totMargin / totRetail * 100
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"days": days,
		"totals": map[string]interface{}{
			"requests":      totReq,
			"retail_usd":    totRetail,
			"wholesale_usd": totWholesale,
			"margin_usd":    totMargin,
			"margin_pct":    totMarginPct,
		},
		"by_model": breakdown,
	})
}

// ── Auth middleware ───────────────────────────────────────────────────────────

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}
		rawKey := strings.TrimPrefix(auth, "Bearer ")

		apiKey, err := keys.Lookup(r.Context(), rawKey)
		if err != nil {
			log.Printf("key lookup error: %v", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		if apiKey == nil {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ctxAPIKey, apiKey)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func callSidecar(path string, body []byte) (*http.Response, error) {
	client := &http.Client{Timeout: 90 * time.Second} // sidecar handles multi-model retry chain
	req, err := http.NewRequest("POST", sidecarURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func adminMiddleware(next http.Handler) http.Handler {
	secret := getEnv("ADMIN_SECRET", "")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret == "" {
			http.Error(w, `{"error":"admin not configured"}`, http.StatusForbidden)
			return
		}
		if r.Header.Get("X-Admin-Secret") != secret {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Admin-Secret, X-Payment")
		w.Header().Set("Access-Control-Expose-Headers", "X-Payment-Required, X-Routed-Subnet, X-RateLimit-Remaining")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Auth handlers ─────────────────────────────────────────────────────────────

func handleAuthRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, `{"error":"email required"}`, http.StatusBadRequest)
		return
	}
	if err := auth.RequestMagicLink(r.Context(), body.Email); err != nil {
		log.Printf("magic link error: %v", err)
		http.Error(w, `{"error":"could not send email"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Check your email"})
}

func handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	sessionToken, err := auth.VerifyMagicLink(r.Context(), token)
	if err != nil {
		appURL := getEnv("APP_URL", "http://localhost:3002")
		http.Redirect(w, r, appURL+"/login?error=expired", http.StatusFound)
		return
	}
	// Return token as JSON — frontend sets the cookie on its own domain
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": sessionToken})
}

// ── Session middleware + dashboard API ────────────────────────────────────────

type ctxSession string
const ctxSessionKey ctxSession = "session"

func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept session from cookie OR Authorization: Bearer header
		var tokenStr string
		if cookie, err := r.Cookie("session"); err == nil {
			tokenStr = cookie.Value
		} else {
			tokenStr = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if tokenStr == "" {
			http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
			return
		}
		sess, err := auth.ParseSession(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxSessionKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func handleUsage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)

	rows, err := db.Pool.Query(r.Context(), `
		SELECT
			DATE(ts)::text AS date,
			SUM(prompt_tokens + completion_tokens) AS tokens,
			COUNT(*) AS requests,
			SUM(cost_usd) AS cost
		FROM usage_events
		WHERE customer_id = $1
		  AND ts >= NOW() - INTERVAL '7 days'
		GROUP BY DATE(ts)
		ORDER BY DATE(ts)
	`, sess.CustomerID)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Day struct {
		Date     string  `json:"date"`
		Tokens   int64   `json:"tokens"`
		Requests int64   `json:"requests"`
		Cost     float64 `json:"cost"`
	}
	var days []Day
	for rows.Next() {
		var d Day
		rows.Scan(&d.Date, &d.Tokens, &d.Requests, &d.Cost)
		days = append(days, d)
	}
	if days == nil {
		days = []Day{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(days)
}

func handleListKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)

	rows, err := db.Pool.Query(r.Context(), `
		SELECT id, key_prefix, name, last_used_at, quota_rpm,
		       (SELECT COUNT(*) FROM usage_events WHERE api_key_id = api_keys.id) AS requests
		FROM api_keys
		WHERE customer_id = $1 AND revoked_at IS NULL
		ORDER BY created_at
	`, sess.CustomerID)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Key struct {
		ID         string  `json:"id"`
		Prefix     string  `json:"prefix"`
		Name       string  `json:"name"`
		LastUsed   *string `json:"last_used_at"`
		QuotaRPM   int     `json:"quota_rpm"`
		Requests   int64   `json:"requests"`
	}
	var keyList []Key
	for rows.Next() {
		var k Key
		rows.Scan(&k.ID, &k.Prefix, &k.Name, &k.LastUsed, &k.QuotaRPM, &k.Requests)
		keyList = append(keyList, k)
	}
	if keyList == nil {
		keyList = []Key{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keyList)
}

func handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		http.Error(w, `{"error":"key id required"}`, http.StatusBadRequest)
		return
	}

	// Scope the update to the session's own customer_id — this prevents one
	// customer from revoking another's key (IDOR). Revocation is a soft delete:
	// setting revoked_at makes keys.Lookup (WHERE revoked_at IS NULL) reject the
	// key on the very next request. No cache to evict — Lookup hits Postgres
	// directly, so the kill is effective immediately.
	tag, err := db.Pool.Exec(r.Context(), `
		UPDATE api_keys
		SET revoked_at = NOW()
		WHERE id = $1 AND customer_id = $2 AND revoked_at IS NULL
	`, keyID, sess.CustomerID)
	if err != nil {
		// Likely a malformed UUID or db error — don't leak details
		http.Error(w, `{"error":"could not revoke key"}`, http.StatusBadRequest)
		return
	}
	if tag.RowsAffected() == 0 {
		// Not found, not owned by this customer, or already revoked
		http.Error(w, `{"error":"key not found"}`, http.StatusNotFound)
		return
	}

	log.Printf("revoked key %s for customer %s", keyID, sess.CustomerID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked", "id": keyID})
}

// ── Billing handlers ──────────────────────────────────────────────────────────

func handleCreateCheckout(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)
	var body struct {
		Pack string `json:"pack"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Pack == "" {
		http.Error(w, `{"error":"pack required"}`, http.StatusBadRequest)
		return
	}
	appURL := getEnv("APP_URL", "http://localhost:3002")
	url, err := billing.CreateCheckoutSession(r.Context(), sess.CustomerID, sess.Email, body.Pack, appURL)
	if err != nil {
		log.Printf("checkout error: %v", err)
		http.Error(w, `{"error":"could not create checkout"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": url})
}

func handleGetBalance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)
	balance, err := billing.GetBalance(r.Context(), sess.CustomerID)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]float64{"balance_usd": balance})
}

// ── Account ───────────────────────────────────────────────────────────────────

func handleGetAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)

	var email string
	var name *string
	var createdAt time.Time
	err := db.Pool.QueryRow(r.Context(),
		`SELECT email, name, created_at FROM customers WHERE id = $1`, sess.CustomerID,
	).Scan(&email, &name, &createdAt)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	displayName := ""
	if name != nil {
		displayName = *name
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"email":      email,
		"name":       displayName,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

func handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if _, err := db.Pool.Exec(r.Context(),
		`UPDATE customers SET name = $1 WHERE id = $2`, body.Name, sess.CustomerID); err != nil {
		http.Error(w, `{"error":"could not update"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "name": body.Name})
}

// ── Billing: history + portal ─────────────────────────────────────────────────

func handleBillingHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)

	rows, err := db.Pool.Query(r.Context(), `
		SELECT amount_usd, credits_usd, status, created_at, paid_at
		FROM credit_purchases
		WHERE customer_id = $1
		ORDER BY created_at DESC
		LIMIT 50
	`, sess.CustomerID)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Purchase struct {
		AmountUSD  float64 `json:"amount_usd"`
		CreditsUSD float64 `json:"credits_usd"`
		Status     string  `json:"status"`
		CreatedAt  string  `json:"created_at"`
		PaidAt     *string `json:"paid_at"`
	}
	var out []Purchase
	for rows.Next() {
		var p Purchase
		var created time.Time
		var paid *time.Time
		rows.Scan(&p.AmountUSD, &p.CreditsUSD, &p.Status, &created, &paid)
		p.CreatedAt = created.Format(time.RFC3339)
		if paid != nil {
			s := paid.Format(time.RFC3339)
			p.PaidAt = &s
		}
		out = append(out, p)
	}
	if out == nil {
		out = []Purchase{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func handleBillingPortal(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)
	appURL := getEnv("APP_URL", "http://localhost:3002")
	url, err := billing.CreatePortalSession(r.Context(), sess.CustomerID, sess.Email, appURL+"/settings")
	if err != nil {
		log.Printf("portal error: %v", err)
		// Most common cause in test mode: the Customer Portal hasn't been
		// activated in the Stripe dashboard yet.
		http.Error(w, `{"error":"billing portal unavailable — enable the Customer Portal in Stripe settings"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": url})
}

func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("Stripe-Signature")
	if err := billing.HandleWebhook(payload, sig); err != nil {
		log.Printf("webhook error: %v", err)
		http.Error(w, "webhook error", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

