package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/Ayoshiss/sentinel-subnet/gateway/db"
)

var jwtSecret = []byte(getEnv("JWT_SECRET", "dev-secret-change-in-prod"))
var appURL = getEnv("APP_URL", "http://localhost:3002")
var resendKey = getEnv("RESEND_API_KEY", "")

// Session holds the data embedded in the JWT cookie
type Session struct {
	CustomerID string `json:"customer_id"`
	Email      string `json:"email"`
}

// RequestMagicLink creates a token, stores it, and emails the link.
// If the email doesn't exist in customers, we create the customer first.
func RequestMagicLink(ctx context.Context, email string) error {
	// Find or create customer
	var customerID string
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO customers (email) VALUES ($1)
		 ON CONFLICT (email) DO UPDATE SET email=EXCLUDED.email
		 RETURNING id`, email).Scan(&customerID)
	if err != nil {
		return fmt.Errorf("upsert customer: %w", err)
	}

	// Generate a random token
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	rawToken := hex.EncodeToString(buf)
	hash := hashToken(rawToken)

	// Store hashed token
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO magic_links (customer_id, token_hash) VALUES ($1, $2)`,
		customerID, hash)
	if err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	// Send email
	magicLink := fmt.Sprintf("%s/auth/verify?token=%s", appURL, rawToken)
	return sendEmail(email, magicLink)
}

// VerifyMagicLink checks the token and returns a signed JWT session string.
func VerifyMagicLink(ctx context.Context, rawToken string) (string, error) {
	hash := hashToken(rawToken)

	var customerID, email string
	err := db.Pool.QueryRow(ctx, `
		UPDATE magic_links ml
		SET used_at = NOW()
		FROM customers c
		WHERE ml.customer_id = c.id
		  AND ml.token_hash = $1
		  AND ml.used_at IS NULL
		  AND ml.expires_at > NOW()
		RETURNING ml.customer_id, c.email
	`, hash).Scan(&customerID, &email)
	if err != nil {
		return "", fmt.Errorf("invalid or expired token")
	}

	// Issue JWT (24h)
	claims := jwt.MapClaims{
		"sub":   customerID,
		"email": email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ParseSession validates the JWT and returns the session.
func ParseSession(tokenStr string) (*Session, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid session")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	return &Session{
		CustomerID: claims["sub"].(string),
		Email:      claims["email"].(string),
	}, nil
}

// sendEmail sends the magic link via Resend API.
func sendEmail(to, magicLink string) error {
	if resendKey == "" {
		// Dev mode: just log the link
		fmt.Printf("\n🔗 Magic link for %s:\n%s\n\n", to, magicLink)
		return nil
	}

	body := map[string]interface{}{
		"from":    "Bhairab <noreply@adhyaaya.com>",
		"to":      []string{to},
		"subject": "Your Bhairab login link",
		"html": fmt.Sprintf(`
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:40px auto;padding:0 20px">
  <div style="font-size:13px;font-weight:600;letter-spacing:0.22em;color:#111">BHAIRAB</div>
  <h2 style="font-size:20px;font-weight:600;color:#111;margin-top:20px">Sign in to Bhairab</h2>
  <p style="color:#555;font-size:14px;line-height:1.6">
    Click the button below to sign in. This link expires in 15 minutes.
  </p>
  <a href="%s" style="display:inline-block;margin:24px 0;padding:12px 24px;background:#E5392B;color:#fff;text-decoration:none;border-radius:8px;font-size:14px;font-weight:600">
    Sign in to Bhairab &rarr;
  </a>
  <p style="color:#999;font-size:12px">
    If you didn't request this, you can safely ignore this email.
  </p>
  <p style="color:#bbb;font-size:11px;margin-top:24px">Bhairab, the guardian of decentralized AI</p>
</div>`, magicLink),
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+resendKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("resend error: %s", resp.Status)
	}
	return nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
