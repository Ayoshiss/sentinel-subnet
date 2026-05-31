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
	"github.com/taogateway/gateway/db"
	"github.com/taogateway/gateway/keys"
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

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/health", handleHealth)
	r.With(authMiddleware).Post("/v1/chat/completions", handleChatCompletions)

	// Admin routes — key management (no auth for now, wire up in Phase 2)
	r.Post("/admin/customers", handleCreateCustomer)
	r.Post("/admin/keys", handleCreateKey)

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
	client := &http.Client{Timeout: 25 * time.Second}
	req, err := http.NewRequest("POST", sidecarURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

