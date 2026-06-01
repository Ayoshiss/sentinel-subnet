package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"fmt"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/taogateway/gateway/auth"
	"github.com/taogateway/gateway/billing"
	"github.com/taogateway/gateway/db"
	"github.com/taogateway/gateway/keys"
	"github.com/taogateway/gateway/ratelimit"
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
	r.With(authMiddleware).Post("/v1/chat/completions", handleChatCompletions)

	// Auth routes — magic link
	r.Post("/auth/request", handleAuthRequest)
	r.Get("/auth/verify", handleAuthVerify)

	// Dashboard API — session required
	r.With(sessionMiddleware).Get("/v1/usage", handleUsage)
	r.With(sessionMiddleware).Get("/v1/keys", handleListKeys)

	// Billing routes
	r.With(sessionMiddleware).Post("/v1/billing/checkout", handleCreateCheckout)
	r.With(sessionMiddleware).Get("/v1/billing/balance", handleGetBalance)
	r.Post("/v1/billing/webhook", handleStripeWebhook)

	// Admin routes — protected by ADMIN_SECRET header
	r.With(adminMiddleware).Post("/admin/customers", handleCreateCustomer)
	r.With(adminMiddleware).Post("/admin/keys", handleCreateKey)

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

// ── Chat completions ──────────────────────────────────────────────────────────

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Context().Value(ctxAPIKey).(*keys.APIKey)
	start := time.Now()

	// ── Rate limiting ──────────────────────────────────────────────────────────
	allowed, remaining, resetAt := ratelimit.Allow(apiKey.ID, apiKey.QuotaRPM)
	if !allowed {
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", apiKey.QuotaRPM))
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(resetAt).Seconds())))
		http.Error(w, `{"error":"rate limit exceeded","type":"rate_limit_error"}`, http.StatusTooManyRequests)
		return
	}
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

	// ── Balance check ──────────────────────────────────────────────────────────
	balance, err := billing.GetBalance(r.Context(), apiKey.CustomerID)
	if err == nil && balance <= 0 {
		http.Error(w, `{"error":"insufficient balance — top up at https://tao-gateway.vercel.app/dashboard","type":"billing_error"}`, http.StatusPaymentRequired)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	// Parse request to extract model + token estimate for billing
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	json.Unmarshal(body, &req)

	resp, err := callSidecar("/query", body)
	if err != nil {
		log.Printf("sidecar error: %v", err)
		keys.RecordUsage(apiKey.ID, apiKey.CustomerID, "SN64-Chutes", req.Model, "error", 0, 0, int(time.Since(start).Milliseconds()), 0)
		http.Error(w, `{"error":"subnet unavailable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	latency := int(time.Since(start).Milliseconds())

	// Parse response to get real token counts
	var openAIResp struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	json.Unmarshal(respBody, &openAIResp)

	// Cost: ~$0.50/M input + $1.50/M output (our price to customer, cost-plus 30%)
	costUSD := (float64(openAIResp.Usage.PromptTokens)*0.50 + float64(openAIResp.Usage.CompletionTokens)*1.50) / 1_000_000

	// ── Deduct balance ─────────────────────────────────────────────────────────
	go billing.DeductBalance(context.Background(), apiKey.CustomerID, costUSD)

	subnet := resp.Header.Get("X-Routed-Subnet")
	if subnet == "" {
		subnet = "SN64-Chutes"
	}

	go keys.RecordUsage(apiKey.ID, apiKey.CustomerID, subnet, req.Model, "ok",
		openAIResp.Usage.PromptTokens, openAIResp.Usage.CompletionTokens, latency, costUSD)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Routed-Subnet", subnet)
	w.Header().Set("X-Latency-Ms", fmt.Sprintf("%d", latency))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Admin-Secret")
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
	sess := r.Context().Value(ctxSessionKey).(*auth.Session)
	balance, err := billing.GetBalance(r.Context(), sess.CustomerID)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]float64{"balance_usd": balance})
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

