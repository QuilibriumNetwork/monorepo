package integration

type Condition func(*Instance) bool

func RightAway(*Instance) bool {
	return true
}

func RankFinalized(rank uint64) Condition {
	return func(in *Instance) bool {
		return in.forks.FinalizedRank() >= rank
	}
}

func RankReached(rank uint64) Condition {
	return func(in *Instance) bool {
		return in.pacemaker.CurrentRank() >= rank
	}
}
