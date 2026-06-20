package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
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
	`)
	if err != nil {
		log.Printf("metrics: could not ensure scan_events table: %v", err)
	}
}

// recordScan persists one scan event. Fire-and-forget: never block or fail a
// scan because telemetry hiccuped.
func recordScan(tier, verdict, source, caller, token string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.Pool.Exec(ctx,
			`INSERT INTO scan_events (tier, verdict, source, caller, token) VALUES ($1,$2,$3,$4,$5)`,
			tier, verdict, source, caller, token)
		if err != nil {
			log.Printf("metrics: record scan failed: %v", err)
		}
	}()
}

// handleScanStats returns aggregate scan telemetry (admin-only). The headline
// numbers for a milestone email: total scans, distinct callers, recent activity.
func handleScanStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type stats struct {
		TotalScans      int64            `json:"totalScans"`
		DistinctCallers int64            `json:"distinctCallers"`
		Last24h         int64            `json:"last24h"`
		Last7d          int64            `json:"last7d"`
		Callers24h      int64            `json:"distinctCallers24h"`
		ByVerdict       map[string]int64 `json:"byVerdict"`
		ByTier          map[string]int64 `json:"byTier"`
	}
	s := stats{ByVerdict: map[string]int64{}, ByTier: map[string]int64{}}

	row := db.Pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(DISTINCT caller),
			COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days'),
			COUNT(DISTINCT caller) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours')
		FROM scan_events`)
	if err := row.Scan(&s.TotalScans, &s.DistinctCallers, &s.Last24h, &s.Last7d, &s.Callers24h); err != nil {
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
