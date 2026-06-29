package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/taogateway/gateway/db"
)

// scan_events is the persistent record of every risk scan — the real
// product-engagement signal (a bot loads the page; only a human runs a scan).
// Powers the milestone metric: how many scans, by how many distinct callers.
func ensureScanTable(ctx context.Context) {
	_, err := db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS scan_events (
			id         BIGSERIAL PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			tier       TEXT,
			verdict    TEXT,
			source     TEXT,
			caller     TEXT,
			token      TEXT
		);
		CREATE INDEX IF NOT EXISTS scan_events_created_idx ON scan_events (created_at);
		-- IP lets us count distinct VISITORS even when the public page shares one
		-- demo key (so all web scans would otherwise look like a single caller).
		ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS ip TEXT;
	`)
	if err != nil {
		log.Printf("metrics: could not ensure scan_events table: %v", err)
	}
}

// recordScan persists one scan event. Fire-and-forget: never block or fail a
// scan because telemetry hiccuped.
func recordScan(tier, verdict, source, caller, token, ip string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.Pool.Exec(ctx,
			`INSERT INTO scan_events (tier, verdict, source, caller, token, ip) VALUES ($1,$2,$3,$4,$5,$6)`,
			tier, verdict, source, caller, token, ip)
		if err != nil {
			log.Printf("metrics: record scan failed: %v", err)
		}
	}()
}

// handleUserStats returns the real account numbers (admin-only): how many people
// entered an email (signups), how many actually clicked the magic link (logins),
// and how many API keys exist.
func handleUserStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var signups, loggedIn, apiKeys, signups7d int64

	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM customers`).Scan(&signups)
	db.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT customer_id) FROM magic_links WHERE used_at IS NOT NULL`).Scan(&loggedIn)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&apiKeys)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM customers WHERE created_at > NOW() - INTERVAL '7 days'`).Scan(&signups7d)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"signups":       signups,  // entered an email
		"loggedIn":      loggedIn, // clicked the magic link
		"apiKeys":       apiKeys,  // created a key
		"signupsLast7d": signups7d,
	})
}

// handleScanRecent lists the most recent scans with timestamps (admin-only), so
// we can see WHEN each scan happened and whether it's a new visitor.
func handleScanRecent(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Pool.Query(r.Context(), `
		SELECT created_at, tier, verdict, COALESCE(ip,''), COALESCE(token,'')
		FROM scan_events ORDER BY created_at DESC LIMIT 25`)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type ev struct {
		At      string `json:"at"`
		Ago     string `json:"ago"`
		Tier    string `json:"tier"`
		Verdict string `json:"verdict"`
		IPTail  string `json:"ipTail"` // last octet only (privacy) — enough to tell visitors apart
		Token   string `json:"token"`
	}
	var out []ev
	for rows.Next() {
		var t time.Time
		var tier, verdict, ip, token string
		if rows.Scan(&t, &tier, &verdict, &ip, &token) != nil {
			continue
		}
		tail := ip
		if i := strings.LastIndexByte(ip, '.'); i >= 0 {
			tail = "…" + ip[i:]
		}
		d := time.Since(t).Round(time.Minute)
		out = append(out, ev{
			At: t.UTC().Format("2006-01-02 15:04 MST"), Ago: d.String(),
			Tier: tier, Verdict: verdict, IPTail: tail,
			Token: token[:min(len(token), 10)],
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleScanStats returns aggregate scan telemetry (admin-only). The headline
// numbers for a milestone email: total scans, distinct callers, recent activity.
func handleScanStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type stats struct {
		TotalScans       int64            `json:"totalScans"`
		DistinctVisitors int64            `json:"distinctVisitors"` // by IP — the real "how many people" number
		Visitors24h      int64            `json:"distinctVisitors24h"`
		DistinctCallers  int64            `json:"distinctCallers"` // by key/wallet (web shares one demo key)
		Last24h          int64            `json:"last24h"`
		Last7d           int64            `json:"last7d"`
		Callers24h       int64            `json:"distinctCallers24h"`
		ByVerdict        map[string]int64 `json:"byVerdict"`
		ByTier           map[string]int64 `json:"byTier"`
	}
	s := stats{ByVerdict: map[string]int64{}, ByTier: map[string]int64{}}

	row := db.Pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(DISTINCT ip),
			COUNT(DISTINCT ip) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours'),
			COUNT(DISTINCT caller),
			COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days'),
			COUNT(DISTINCT caller) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours')
		FROM scan_events`)
	if err := row.Scan(&s.TotalScans, &s.DistinctVisitors, &s.Visitors24h, &s.DistinctCallers, &s.Last24h, &s.Last7d, &s.Callers24h); err != nil {
		http.Error(w, `{"error":"stats query failed"}`, http.StatusInternalServerError)
		log.Printf("metrics: stats query: %v", err)
		return
	}

	if rows, err := db.Pool.Query(ctx, `SELECT verdict, COUNT(*) FROM scan_events GROUP BY verdict`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int64
			if rows.Scan(&k, &n) == nil {
				s.ByVerdict[k] = n
			}
		}
	}
	if rows, err := db.Pool.Query(ctx, `SELECT tier, COUNT(*) FROM scan_events GROUP BY tier`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int64
			if rows.Scan(&k, &n) == nil {
				s.ByTier[k] = n
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}
