// Package pricing holds upstream wholesale rates (our cost of goods) and the
// retail rate we bill customers. Hardcoded on purpose: at this scale upstream
// rates change rarely, a deploy is cheap, and git history is a cleaner audit
// trail of "what we believed margin was on a given day" than a mutable table.
//
// To move to dynamic, DB-backed rates later, replace Wholesale() with a cached
// table lookup, callers don't change.
package pricing

import "log"

// rate is USD per 1,000,000 tokens.
type rate struct {
	InPerM  float64
	OutPerM float64
}

// wholesale = what the upstream provider charges US (cost of goods sold).
// Keyed by the model that ACTUALLY served the request (response.model), not the
// model the customer requested, the router/fallback/backstop may differ.
//
// Sources: Chutes published per-model rates; Groq list price (used for COGS
// modelling even while on the free tier, so margin reflects true unit economics
// once free quota is exceeded). Rates marked TODO need confirmation against the
// provider's current pricing page.
var wholesale = map[string]rate{
	// ── Chutes SN64 ──
	"deepseek-ai/DeepSeek-V3.2-TEE":          {0.27, 0.27}, // TODO confirm
	"google/gemma-4-31B-turbo-TEE":           {0.15, 0.42},
	"unsloth/Mistral-Nemo-Instruct-2407-TEE": {0.02, 0.10},
	"moonshotai/Kimi-K2.6-TEE":               {0.50, 1.50}, // TODO confirm
	"Qwen/Qwen3-32B-TEE":                     {0.15, 0.42}, // TODO confirm
	"Qwen/Qwen3.6-27B-TEE":                   {0.15, 0.42}, // TODO confirm
	"Qwen/Qwen2.5-Coder-32B-Instruct-TEE":    {0.15, 0.42}, // TODO confirm
	// ── Groq backstop ──
	"llama-3.3-70b-versatile": {0.59, 0.79}, // Groq list price
}

// Retail = what we charge the customer, regardless of which backend served it.
// (Cost-plus model; on the rare Groq backstop we may earn thinner margin or eat
// it to preserve the SLA, wholesale tracking is exactly how we'll see that.)
const (
	RetailInPerM  = 0.50
	RetailOutPerM = 1.50
)

// Wholesale returns our cost (USD) for a request served by `model` with the
// given token counts. Returns 0 and logs if the model has no known rate, so a
// missing entry surfaces loudly instead of silently understating COGS.
func Wholesale(model string, promptTok, completionTok int) float64 {
	r, ok := wholesale[model]
	if !ok {
		log.Printf("pricing: no wholesale rate for model %q, COGS recorded as 0", model)
		return 0
	}
	return (float64(promptTok)*r.InPerM + float64(completionTok)*r.OutPerM) / 1_000_000
}

// Retail returns what we bill the customer for the given token counts.
func Retail(promptTok, completionTok int) float64 {
	return (float64(promptTok)*RetailInPerM + float64(completionTok)*RetailOutPerM) / 1_000_000
}
