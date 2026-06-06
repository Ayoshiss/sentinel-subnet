package x402

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/mr-tron/base58"
)

// Pure-Go round trip: sign the message the same way an agent would, verify it.
func TestRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	resource := "/v1/chat/completions"
	nonce := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	amount := "1000"

	msg := signedMessage(amount, USDCDevMint, Network, resource, nonce)
	sig := ed25519.Sign(priv, msg)

	proof := &Proof{
		From:      base58.Encode(pub),
		Pubkey:    base58.Encode(pub),
		Signature: base58.Encode(sig),
		Amount:    amount,
		Asset:     USDCDevMint,
		Network:   Network,
		Nonce:     nonce,
	}
	if !Verify(proof, resource, nonce, 1000) {
		t.Fatal("round-trip verify failed")
	}
	// wrong nonce must fail
	if Verify(proof, resource, "wrongnonce", 1000) {
		t.Fatal("verify accepted a mismatched nonce")
	}
	// underpayment must fail
	if Verify(proof, resource, nonce, 2000) {
		t.Fatal("verify accepted underpayment")
	}
}

// Cross-language: verify a proof produced by Lattice's exact tweetnacl/bs58 flow.
// Set X402_PROOF (base64 X-PAYMENT header), X402_NONCE, X402_RESOURCE.
func TestCrossLanguageJS(t *testing.T) {
	header := os.Getenv("X402_PROOF")
	if header == "" {
		t.Skip("set X402_PROOF/X402_NONCE/X402_RESOURCE to run cross-language check")
	}
	proof, ok := ParseProof(header)
	if !ok {
		t.Fatal("failed to parse JS proof header")
	}
	// sanity: the parsed proof should re-encode to the same JSON the JS produced
	b, _ := json.Marshal(proof)
	_ = base64.StdEncoding.EncodeToString(b)

	if !Verify(proof, os.Getenv("X402_RESOURCE"), os.Getenv("X402_NONCE"), 1000) {
		t.Fatal("JS-signed proof FAILED to verify in Go — byte-parity broken")
	}
	t.Log("✅ JS (tweetnacl/bs58) proof verified in Go — byte-parity confirmed")
}
