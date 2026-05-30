package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Sidecar URL — Python FastAPI process handling dendrite calls
var sidecarURL = getEnv("SIDECAR_URL", "http://localhost:8001")

// API key gate — replace with real key store in Phase 2
var validAPIKey = getEnv("API_KEY", "sk_live_taogateway_dev")

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/health", handleHealth)
	r.With(authMiddleware).Post("/v1/chat/completions", handleChatCompletions)

	addr := ":" + getEnv("PORT", "8080")
	log.Printf("TAO Gateway listening on %s → sidecar %s", addr, sidecarURL)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "subnet": "SN64-Chutes"})
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MB cap
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}

	// Forward to Python sidecar which handles dendrite + Chutes
	resp, err := callSidecar("/query", body)
	if err != nil {
		log.Printf("sidecar error: %v", err)
		http.Error(w, `{"error":"subnet unavailable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Pass through headers that matter
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Routed-Subnet", resp.Header.Get("X-Routed-Subnet"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func callSidecar(path string, body []byte) (*http.Response, error) {
	client := &http.Client{Timeout: 25 * time.Second}
	req, err := http.NewRequest("POST", sidecarURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != validAPIKey {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
