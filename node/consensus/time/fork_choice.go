package time

import (
	"math"
	"math/big"

	"github.com/iden3/go-iden3-crypto/ff"
)

const SCALE uint64 = 0xffffffffffffffff

type Frame struct {
	Distance      *big.Int // 256-bit distance; 0 is best
	Seniority     uint64   // 0 ... SCALE (0 == evicted / black-listed)
	ProverAddress []byte
}

type Branch struct {
	Frames []Frame
}

// Params == all tunables.
type Params struct {
	RMax        *big.Int // maximum distance (constant)
	WrNumer     uint64   // distance weight numerator
	WpNumer     uint64   // seniority weight numerator
	WDenom      uint64   // common weight denominator
	AlNumer     uint64   // α numerator
	AlDenom     uint64   // α denominator
	BlendWindow int      // m — last m rounds window
	BetaNumer   uint64   // β numerator
	BetaDenom   uint64   // β denominator
	Epsilon     uint64   // tie margin in SCALE units
}

var RMaxDenom *big.Int
var DefaultForkChoiceParams Params

func init() {
	RMaxDenom = ff.Modulus()
	DefaultForkChoiceParams = Params{
		RMax:        new(big.Int).SetUint64(math.MaxUint64),
		WrNumer:     7,
		WpNumer:     3,
		WDenom:      10,
		AlNumer:     9,
		AlDenom:     10,
		BlendWindow: 5,
		BetaNumer:   1,
		BetaDenom:   10,
		Epsilon:     0,
	}
}

// ForkChoice returns the index of the branch every honest player should
// extend this round.  `prevChoice` is the branch you extended last round
// (pass 0 the first time).
func ForkChoice(branches []Branch, cfg Params, prevChoice int) int {
	bestIdx := prevChoice
	bestScore := new(big.Int)

	// Calculate score for current choice first
	if prevChoice < len(branches) {
		bestScore = branchScore(branches[prevChoice], cfg)
	}

	for i, br := range branches {
		score := branchScore(br, cfg)
		if score.Cmp(new(big.Int).Add(
			bestScore,
			new(big.Int).SetUint64(cfg.Epsilon),
		)) > 0 {
			bestScore = score
			bestIdx = i
		}
	}
	return bestIdx
}

func branchScore(br Branch, cfg Params) *big.Int {
	if len(br.Frames) == 0 {
		return big.NewInt(0) // empty fork can’t win
	}

	// 1. Exponentially-decayed raw score
	raw := big.NewInt(0)

	alphaNum := cfg.AlNumer
	alphaDen := cfg.AlDenom

	// iterate oldest to newest
	for _, frame := range br.Frames {
		rho := new(big.Int).SetUint64(rhoScaled(frame.Distance, cfg.RMax))
		pi := new(big.Int).SetUint64(clamp(frame.Seniority, 0, SCALE))

		frameScore := new(big.Int).Quo(
			new(big.Int).Add(
				new(big.Int).Mul(new(big.Int).SetUint64(cfg.WrNumer), rho),
				new(big.Int).Mul(new(big.Int).SetUint64(cfg.WpNumer), pi),
			),
			new(big.Int).SetUint64(cfg.WDenom),
		)
		raw = new(big.Int).Add(
			new(big.Int).Quo(
				new(big.Int).Mul(raw, new(big.Int).SetUint64(alphaNum)),
				new(big.Int).SetUint64(alphaDen),
			),
			frameScore,
		)
	}

	// 2. Blend bonus
	m := cfg.BlendWindow
	if m > len(br.Frames) {
		m = len(br.Frames)
	}
	if m == 0 {
		return big.NewInt(0)
	}

	uniq := make(map[string]struct{}, m)
	for i := len(br.Frames) - m; i < len(br.Frames); i++ {
		if br.Frames[i].Seniority > 0 { // ignore evicted players
			uniq[string(br.Frames[i].ProverAddress)] = struct{}{}
		}
	}
	blendScaled := new(big.Int).Quo(
		new(big.Int).Mul(
			new(big.Int).SetUint64(uint64(len(uniq))),
			new(big.Int).SetUint64(SCALE),
		),
		new(big.Int).SetUint64(uint64(m)),
	)
	divBonus := new(big.Int).Add(
		new(big.Int).SetUint64(SCALE),
		new(big.Int).Quo(
			new(big.Int).Mul(new(big.Int).SetUint64(cfg.BetaNumer), blendScaled),
			new(big.Int).SetUint64(cfg.BetaDenom),
		),
	)

	// 3. Finalized score
	return new(big.Int).Quo(
		new(big.Int).Mul(raw, divBonus),
		new(big.Int).SetUint64(SCALE),
	)
}

// rhoScaled = ((RMax − rank) * SCALE) / RMax   ∈ [0,SCALE]
func rhoScaled(rank, rMax *big.Int) uint64 {
	tmp := new(big.Int).Sub(rMax, rank)          // RMax − rank
	tmp.Mul(tmp, big.NewInt(0).SetUint64(SCALE)) // * SCALE
	tmp.Quo(tmp, rMax)                           // / RMax
	if tmp.Sign() < 0 {
		return 0
	}
	if tmp.Cmp(big.NewInt(0).SetUint64(SCALE)) > 0 {
		return SCALE
	}
	return tmp.Uint64()
}

func clamp(x, lo, hi uint64) uint64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}
