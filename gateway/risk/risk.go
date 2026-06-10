// Package risk gathers LIVE on-chain risk signals for a token so Bhairab's AI can
// reason over FACTS, not vibes. This is the moat of the pre-transaction risk scan:
// the AI is only as good as the fresh signals we feed it.
//
// v1 covers the "market" risk axis on Solana via DexScreener (free, no API key):
// price, 24h move, liquidity, volume, pair age. Deterministic heuristics flag the
// obvious dangers (crashing, illiquid, brand-new, wash-traded) so the endpoint has
// a trustworthy floor even if the LLM is unreachable.
//
// Fast-follow axes (not yet wired): contract/honeypot checks, fresh-exploit feeds,
// RPC/network health, sanctions & jurisdiction policy.
package risk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"
)

const dexScreenerBase = "https://api.dexscreener.com/latest/dex/tokens/"

// Signals is the ground-truth packet the AI (and the deterministic fallback)
// reason over.
type Signals struct {
	Chain          string   `json:"chain"`
	Token          string   `json:"token"`
	Found          bool     `json:"found"`
	Symbol         string   `json:"symbol,omitempty"`
	Name           string   `json:"name,omitempty"`
	PriceUSD       float64  `json:"priceUsd"`
	PriceChange24h float64  `json:"priceChange24hPct"`
	LiquidityUSD   float64  `json:"liquidityUsd"`
	Volume24hUSD   float64  `json:"volume24hUsd"`
	PairCount      int      `json:"pairCount"`
	AgeDays        float64  `json:"ageDays"`
	TopDex         string   `json:"topDex,omitempty"`
	Heuristics     []string `json:"heuristics"`
	Source         string   `json:"source"`
}

type dexResp struct {
	Pairs []struct {
		ChainID     string `json:"chainId"`
		DexID       string `json:"dexId"`
		PriceUSD    string `json:"priceUsd"`
		PriceChange struct {
			H24 float64 `json:"h24"`
		} `json:"priceChange"`
		Liquidity struct {
			USD float64 `json:"usd"`
		} `json:"liquidity"`
		Volume struct {
			H24 float64 `json:"h24"`
		} `json:"volume"`
		PairCreatedAt int64 `json:"pairCreatedAt"` // unix ms
		BaseToken     struct {
			Name   string `json:"name"`
			Symbol string `json:"symbol"`
		} `json:"baseToken"`
	} `json:"pairs"`
}

// Gather pulls live signals for a token. It never returns a nil *Signals on a
// recoverable miss — "no data" is itself a risk signal the caller should surface.
func Gather(chain, token string) (*Signals, error) {
	s := &Signals{Chain: chain, Token: token, Source: "dexscreener"}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(dexScreenerBase + token)
	if err != nil {
		s.Heuristics = []string{"signal_fetch_failed: could not reach market-data source — treat as unknown risk"}
		return s, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	var dr dexResp
	if err := json.Unmarshal(b, &dr); err != nil {
		s.Heuristics = []string{"signal_parse_failed: market-data source returned unexpected shape"}
		return s, err
	}
	if len(dr.Pairs) == 0 {
		s.Found = false
		s.Heuristics = []string{"no_market_data: token not listed on any tracked DEX — unknown or illiquid (high risk)"}
		return s, nil
	}

	// The deepest-liquidity pair is the most representative venue.
	sort.Slice(dr.Pairs, func(i, j int) bool {
		return dr.Pairs[i].Liquidity.USD > dr.Pairs[j].Liquidity.USD
	})
	top := dr.Pairs[0]

	s.Found = true
	s.Symbol = top.BaseToken.Symbol
	s.Name = top.BaseToken.Name
	s.PriceUSD, _ = strconv.ParseFloat(top.PriceUSD, 64)
	s.PriceChange24h = top.PriceChange.H24
	s.LiquidityUSD = top.Liquidity.USD
	s.Volume24hUSD = top.Volume.H24
	s.PairCount = len(dr.Pairs)
	s.TopDex = top.DexID
	if top.PairCreatedAt > 0 {
		s.AgeDays = time.Since(time.UnixMilli(top.PairCreatedAt)).Hours() / 24
	}
	s.Heuristics = heuristics(s)
	return s, nil
}

// heuristics derives deterministic red flags from the raw signals. These are the
// non-negotiable facts; the LLM may add nuance but must not override them.
func heuristics(s *Signals) []string {
	var h []string
	if s.LiquidityUSD > 0 && s.LiquidityUSD < 10000 {
		h = append(h, "low_liquidity: pool <$10k — trivially manipulated and hard to exit (rug risk)")
	}
	if s.PriceChange24h <= -30 {
		h = append(h, fmt.Sprintf("crashing: down %.1f%% in 24h", s.PriceChange24h))
	}
	if s.PriceChange24h >= 100 {
		h = append(h, fmt.Sprintf("pump_spike: up %.1f%% in 24h — possible manipulation / FOMO trap", s.PriceChange24h))
	}
	if s.LiquidityUSD > 0 && s.Volume24hUSD/s.LiquidityUSD > 10 {
		h = append(h, "abnormal_volume: 24h volume >10x liquidity — possible wash trading")
	}
	if s.AgeDays > 0 && s.AgeDays < 3 {
		h = append(h, fmt.Sprintf("new_token: pair only %.1f days old — elevated rug risk", s.AgeDays))
	}
	if len(h) == 0 {
		h = append(h, "no_red_flags_in_market_data")
	}
	return h
}

// Severe reports whether the deterministic signals alone justify a hard stop —
// the floor that holds even if the LLM is unavailable or over-optimistic.
func (s *Signals) Severe() bool {
	if !s.Found {
		return false // unknown ≠ severe; that's a caution
	}
	if s.PriceChange24h <= -40 {
		return true
	}
	if s.LiquidityUSD > 0 && s.LiquidityUSD < 2000 {
		return true
	}
	if s.AgeDays > 0 && s.AgeDays < 1 && s.LiquidityUSD < 25000 {
		return true
	}
	return false
}
