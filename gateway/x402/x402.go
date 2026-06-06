// Package x402 implements Bhairab's side of the x402 "pay-per-request" dance,
// byte-compatible with Lattice's relay (relay/src/x402.ts) so an autonomous
// agent uses the IDENTICAL flow + wallet to pay both Bhairab (to think) and
// Lattice (to act). This is the integration point between the two projects.
//
// Model (mirrors Lattice): ed25519 signed authorization, not on-chain
// settlement. The agent signs a JSON message authorizing payment; we verify the
// signature. Real USDC settlement is a fast-follow.
package x402

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"

	"github.com/mr-tron/base58"
)

// Solana devnet USDC mint (same constant Lattice uses).
const USDCDevMint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

// Network identifier in the signed message.
const Network = "solana"

// Recipient (our USDC address) — set via env; placeholder is the system program.
func Recipient() string {
	if r := os.Getenv("X402_USDC_RECIPIENT"); r != "" {
		return r
	}
	return "11111111111111111111111111111111"
}

// PaymentRequired is the 402 envelope handed to the client (base64-encoded).
type PaymentRequired struct {
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	Asset             string `json:"asset"`
	Recipient         string `json:"recipient"`
	MaxAmountRequired string `json:"maxAmountRequired"`
	Resource          string `json:"resource"`
	MimeType          string `json:"mimeType"`
	Nonce             string `json:"nonce"`
}

// Build402 returns the base64 envelope header and the issued nonce. priceMicro
// is the price in micro-USDC (6 decimals); e.g. 1000 = 0.001 USDC.
func Build402(resource string, priceMicro int64) (header string, nonce string) {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	nonce = hex.EncodeToString(buf)
	payload := PaymentRequired{
		Scheme:            "exact",
		Network:           Network,
		Asset:             USDCDevMint,
		Recipient:         Recipient(),
		MaxAmountRequired: strconv.FormatInt(priceMicro, 10),
		Resource:          resource,
		MimeType:          "application/json",
		Nonce:             nonce,
	}
	b, _ := json.Marshal(payload)
	return base64.StdEncoding.EncodeToString(b), nonce
}

// Proof is the parsed X-PAYMENT header the agent sends back.
type Proof struct {
	From      string `json:"from"`      // base58 ed25519 pubkey
	Pubkey    string `json:"pubkey"`    // same as from (explicit)
	Signature string `json:"signature"` // base58 nacl/ed25519 detached signature
	Amount    string `json:"amount"`
	Asset     string `json:"asset"`
	Network   string `json:"network"`
	Nonce     string `json:"nonce"`
}

// ParseProof decodes the base64 X-PAYMENT header.
func ParseProof(header string) (*Proof, bool) {
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, false
	}
	var p Proof
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false
	}
	return &p, true
}

// signedMessage reconstructs the exact JSON bytes the agent signed. Field order
// (amount, asset, network, resource, nonce) and compactness must byte-match
// Lattice's buildSignedMessage / JS JSON.stringify.
type signedMsg struct {
	Amount   string `json:"amount"`
	Asset    string `json:"asset"`
	Network  string `json:"network"`
	Resource string `json:"resource"`
	Nonce    string `json:"nonce"`
}

func signedMessage(amount, asset, network, resource, nonce string) []byte {
	b, _ := json.Marshal(signedMsg{
		Amount:   amount,
		Asset:    asset,
		Network:  network,
		Resource: resource,
		Nonce:    nonce,
	})
	return b
}

// Verify checks the ed25519 signature over the reconstructed message, that the
// authorized amount is at least minMicro, and (if provided) that the nonce
// matches the one we issued. resource must be the endpoint the 402 was for.
func Verify(p *Proof, resource, expectedNonce string, minMicro int64) bool {
	if p == nil || p.From == "" || p.Pubkey == "" || p.Signature == "" {
		return false
	}
	amt, err := strconv.ParseInt(p.Amount, 10, 64)
	if err != nil || amt < minMicro {
		return false
	}
	if expectedNonce != "" && p.Nonce != expectedNonce {
		return false
	}
	pubkey, err := base58.Decode(p.Pubkey)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base58.Decode(p.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := signedMessage(p.Amount, p.Asset, p.Network, resource, p.Nonce)
	return ed25519.Verify(pubkey, msg, sig)
}
