package time

import (
	"math"
	"math/big"
	"testing"
)

func TestFrame(t *testing.T) {
	frame := Frame{
		Distance:      big.NewInt(100),
		Seniority:     500,
		ProverAddress: []byte("test_address"),
	}

	if frame.Distance.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("Expected distance 100, got %v", frame.Distance)
	}
	if frame.Seniority != 500 {
		t.Errorf("Expected seniority 500, got %d", frame.Seniority)
	}
	if string(frame.ProverAddress) != "test_address" {
		t.Errorf("Expected address 'test_address', got %s", string(frame.ProverAddress))
	}
}

func TestBranch(t *testing.T) {
	frames := []Frame{
		{Distance: big.NewInt(50), Seniority: 100, ProverAddress: []byte("addr1")},
		{Distance: big.NewInt(75), Seniority: 200, ProverAddress: []byte("addr2")},
	}
	branch := Branch{Frames: frames}

	if len(branch.Frames) != 2 {
		t.Errorf("Expected 2 frames, got %d", len(branch.Frames))
	}
}

func TestDefaultForkChoiceParams(t *testing.T) {
	cfg := DefaultForkChoiceParams

	if cfg.RMax.Cmp(new(big.Int).SetUint64(math.MaxUint64)) != 0 {
		t.Errorf("Expected RMax to be ff.Modulus(), got %v", cfg.RMax)
	}
	if cfg.WrNumer != 7 {
		t.Errorf("Expected WrNumer 7, got %d", cfg.WrNumer)
	}
	if cfg.WpNumer != 3 {
		t.Errorf("Expected WpNumer 3, got %d", cfg.WpNumer)
	}
	if cfg.WDenom != 10 {
		t.Errorf("Expected WDenom 10, got %d", cfg.WDenom)
	}
	if cfg.AlNumer != 9 {
		t.Errorf("Expected AlNumer 9, got %d", cfg.AlNumer)
	}
	if cfg.AlDenom != 10 {
		t.Errorf("Expected AlDenom 10, got %d", cfg.AlDenom)
	}
	if cfg.BlendWindow != 5 {
		t.Errorf("Expected BlendWindow 5, got %d", cfg.BlendWindow)
	}
	if cfg.BetaNumer != 1 {
		t.Errorf("Expected BetaNumer 1, got %d", cfg.BetaNumer)
	}
	if cfg.BetaDenom != 10 {
		t.Errorf("Expected BetaDenom 10, got %d", cfg.BetaDenom)
	}
	if cfg.Epsilon != 0 {
		t.Errorf("Expected Epsilon 0, got %d", cfg.Epsilon)
	}
}

func TestClamp(t *testing.T) {
	tests := []struct {
		x, lo, hi, expected uint64
	}{
		{5, 0, 10, 5},   // within bounds
		{0, 0, 10, 0},   // at lower bound
		{10, 0, 10, 10}, // at upper bound
		{15, 0, 10, 10}, // above upper bound
		{5, 8, 12, 8},   // below lower bound
	}

	for i, test := range tests {
		result := clamp(test.x, test.lo, test.hi)
		if result != test.expected {
			t.Errorf("Test %d: clamp(%d, %d, %d) = %d, expected %d",
				i, test.x, test.lo, test.hi, result, test.expected)
		}
	}
}

func TestRhoScaled(t *testing.T) {
	rMax := big.NewInt(1000)

	tests := []struct {
		rank     *big.Int
		expected uint64
	}{
		{big.NewInt(0), SCALE},       // best rank
		{big.NewInt(500), SCALE / 2}, // middle rank
		{big.NewInt(1000), 0},        // worst rank
		{big.NewInt(1500), 0},        // rank exceeds rMax
	}

	for i, test := range tests {
		result := rhoScaled(test.rank, rMax)
		if result != test.expected {
			t.Errorf("Test %d: rhoScaled(%v, %v) = %d, expected %d",
				i, test.rank, rMax, result, test.expected)
		}
	}
}

func TestBranchScoreEmptyBranch(t *testing.T) {
	cfg := DefaultForkChoiceParams
	emptyBranch := Branch{Frames: []Frame{}}

	score := branchScore(emptyBranch, cfg)
	if score.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Expected empty branch score to be 0, got %d", score)
	}
}

func TestBranchScoreSingleFrame(t *testing.T) {
	cfg := DefaultForkChoiceParams
	cfg.RMax = big.NewInt(1000) // smaller for easier testing

	frame := Frame{
		Distance:      big.NewInt(0), // best distance
		Seniority:     SCALE,         // best seniority
		ProverAddress: []byte("addr1"),
	}
	branch := Branch{Frames: []Frame{frame}}

	score := branchScore(branch, cfg)
	if score.Cmp(big.NewInt(0)) == 0 {
		t.Error("Expected non-zero score for good frame")
	}
}

func TestBranchScoreMultipleFrames(t *testing.T) {
	cfg := DefaultForkChoiceParams
	cfg.RMax = big.NewInt(1000)

	frames := []Frame{
		{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
		{Distance: big.NewInt(100), Seniority: SCALE / 2, ProverAddress: []byte("addr2")},
		{Distance: big.NewInt(200), Seniority: SCALE / 4, ProverAddress: []byte("addr3")},
	}
	branch := Branch{Frames: frames}

	score := branchScore(branch, cfg)
	if score.Cmp(big.NewInt(0)) == 0 {
		t.Error("Expected non-zero score for multi-frame branch")
	}
}

func TestBranchScoreBlendBonus(t *testing.T) {
	cfg := DefaultForkChoiceParams
	cfg.RMax = big.NewInt(1000)
	cfg.BlendWindow = 3

	// Branch with diverse provers (should get blend bonus)
	diverseFrames := []Frame{
		{Distance: big.NewInt(100), Seniority: SCALE - 20, ProverAddress: []byte("addr1")},
		{Distance: big.NewInt(100), Seniority: SCALE - 20, ProverAddress: []byte("addr2")},
		{Distance: big.NewInt(100), Seniority: SCALE, ProverAddress: []byte("addr3")},
	}
	diverseBranch := Branch{Frames: diverseFrames}

	// Branch with same prover (should get less blend bonus)
	sameFrames := []Frame{
		{Distance: big.NewInt(100), Seniority: SCALE, ProverAddress: []byte("addr1")},
		{Distance: big.NewInt(100), Seniority: SCALE, ProverAddress: []byte("addr1")},
		{Distance: big.NewInt(100), Seniority: SCALE, ProverAddress: []byte("addr1")},
	}
	sameBranch := Branch{Frames: sameFrames}

	diverseScore := branchScore(diverseBranch, cfg)
	sameScore := branchScore(sameBranch, cfg)

	if diverseScore.Cmp(sameScore) <= 0 {
		t.Errorf("Expected diverse branch to score higher than same-prover branch, got diverse=%s same=%s",
			diverseScore.String(), sameScore.String())
	}
}

func TestBranchScoreEvictedPlayers(t *testing.T) {
	cfg := DefaultForkChoiceParams
	cfg.RMax = big.NewInt(1000)

	// Branch with evicted players (seniority = 0)
	frames := []Frame{
		{Distance: big.NewInt(100), Seniority: 0, ProverAddress: []byte("addr1")}, // evicted
		{Distance: big.NewInt(100), Seniority: SCALE, ProverAddress: []byte("addr2")},
		{Distance: big.NewInt(100), Seniority: 0, ProverAddress: []byte("addr3")}, // evicted
	}
	branch := Branch{Frames: frames}

	score := branchScore(branch, cfg)
	// Should still get some score from non-evicted player
	if score.Cmp(big.NewInt(0)) == 0 {
		t.Error("Expected non-zero score even with some evicted players")
	}
}

func TestForkChoiceBasic(t *testing.T) {
	cfg := DefaultForkChoiceParams

	// Better branch (lower distance, higher seniority)
	betterBranch := Branch{
		Frames: []Frame{
			{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
		},
	}

	// Worse branch (higher distance, lower seniority)
	worseBranch := Branch{
		Frames: []Frame{
			{Distance: big.NewInt(500), Seniority: SCALE / 2, ProverAddress: []byte("addr2")},
		},
	}

	branches := []Branch{worseBranch, betterBranch}
	choice := ForkChoice(branches, cfg, 0)

	if choice != 1 {
		t.Errorf("Expected to choose branch 1 (better), got %d", choice)
	}
}

func TestForkChoicePerfectDistance(t *testing.T) {
	cfg := DefaultForkChoiceParams

	// Better branch (lower distance, higher seniority)
	betterBranch := Branch{
		Frames: []Frame{
			{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
			{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
			{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
			{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
			{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
			{Distance: big.NewInt(0), Seniority: SCALE, ProverAddress: []byte("addr1")},
		},
	}

	// Worse branch (lower seniority)
	worseBranch := Branch{
		Frames: []Frame{
			{Distance: big.NewInt(0), Seniority: SCALE / 2, ProverAddress: []byte("addr2")},
			{Distance: big.NewInt(0), Seniority: SCALE / 2, ProverAddress: []byte("addr3")},
			{Distance: big.NewInt(0), Seniority: SCALE / 2, ProverAddress: []byte("addr4")},
			{Distance: big.NewInt(0), Seniority: SCALE / 2, ProverAddress: []byte("addr5")},
			{Distance: big.NewInt(0), Seniority: SCALE / 2, ProverAddress: []byte("addr6")},
			{Distance: big.NewInt(0), Seniority: SCALE / 2, ProverAddress: []byte("addr7")},
		},
	}

	branches := []Branch{worseBranch, betterBranch}
	choice := ForkChoice(branches, cfg, 0)

	if choice != 1 {
		t.Errorf("Expected to choose branch 1 (better), got %d", choice)
	}
}

func TestForkChoiceEmptyBranches(t *testing.T) {
	cfg := DefaultForkChoiceParams
	branches := []Branch{}

	choice := ForkChoice(branches, cfg, 0)
	if choice != 0 {
		t.Errorf("Expected choice 0 for empty branches, got %d", choice)
	}
}

func TestForkChoiceAllEmptyBranches(t *testing.T) {
	cfg := DefaultForkChoiceParams
	branches := []Branch{
		{Frames: []Frame{}},
		{Frames: []Frame{}},
		{Frames: []Frame{}},
	}

	choice := ForkChoice(branches, cfg, 1)
	if choice != 1 {
		t.Errorf("Expected to stick with previous choice 1 when all branches empty, got %d", choice)
	}
}

func BenchmarkBranchScore(b *testing.B) {
	cfg := DefaultForkChoiceParams
	frames := make([]Frame, 100)
	for i := 0; i < 100; i++ {
		frames[i] = Frame{
			Distance:      big.NewInt(int64(i * 10)),
			Seniority:     SCALE / 2,
			ProverAddress: []byte("test_address"),
		}
	}
	branch := Branch{Frames: frames}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		branchScore(branch, cfg)
	}
}

func BenchmarkForkChoice(b *testing.B) {
	cfg := DefaultForkChoiceParams

	branches := make([]Branch, 10)
	for i := 0; i < 10; i++ {
		frames := make([]Frame, 50)
		for j := 0; j < 50; j++ {
			frames[j] = Frame{
				Distance:      big.NewInt(int64(j * 10)),
				Seniority:     SCALE / 2,
				ProverAddress: []byte("test_address"),
			}
		}
		branches[i] = Branch{Frames: frames}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ForkChoice(branches, cfg, 0)
	}
}
