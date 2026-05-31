package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/taogateway/gateway/db"
)

// APIKey holds the data we need per request after a successful lookup.
type APIKey struct {
	ID         string
	CustomerID string
	QuotaRPM   int
	QuotaTPM   int
}

// Generate creates a new API key for a customer, inserts it into the DB,
// and returns the raw key (shown once — never stored).
func Generate(ctx context.Context, customerID, name string) (rawKey string, err error) {
	// 32 random bytes → hex → prefix
	buf := make([]byte, 24)
	if _, err = rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	rawKey = "sk_live_" + hex.EncodeToString(buf)
	prefix := rawKey[:12] // "sk_live_XXXX"

	hash := hashKey(rawKey)

	_, err = db.Pool.Exec(ctx, `
		INSERT INTO api_keys (customer_id, key_hash, key_prefix, name)
		VALUES ($1, $2, $3, $4)
	`, customerID, hash, prefix, name)
	if err != nil {
		return "", fmt.Errorf("insert key: %w", err)
	}

	return rawKey, nil
}

// Lookup validates a raw key against the DB and returns the APIKey metadata.
// Returns nil, nil if the key doesn't exist or is revoked.
func Lookup(ctx context.Context, rawKey string) (*APIKey, error) {
	hash := hashKey(rawKey)

	var k APIKey
	err := db.Pool.QueryRow(ctx, `
		SELECT id, customer_id, quota_rpm, quota_tpm
		FROM api_keys
		WHERE key_hash = $1
		  AND revoked_at IS NULL
	`, hash).Scan(&k.ID, &k.CustomerID, &k.QuotaRPM, &k.QuotaTPM)

	if err != nil {
		// pgx returns pgx.ErrNoRows — treat as invalid key (return nil, nil)
		return nil, nil
	}

	// Fire-and-forget last_used_at update
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		db.Pool.Exec(ctx2, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, k.ID)
	}()

	return &k, nil
}

// RecordUsage writes a usage event to Postgres (async — best effort).
func RecordUsage(keyID, customerID, subnet, model, status string, promptTok, completionTok, latencyMs int, costUSD float64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db.Pool.Exec(ctx, `
		INSERT INTO usage_events
			(api_key_id, customer_id, subnet, model, prompt_tokens, completion_tokens, latency_ms, status, cost_usd)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, keyID, customerID, subnet, model, promptTok, completionTok, latencyMs, status, costUSD)
}

func hashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
