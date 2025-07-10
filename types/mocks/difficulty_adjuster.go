package mocks

import "github.com/stretchr/testify/mock"

type MockDifficultyAdjuster struct {
	mock.Mock
}

func (m *MockDifficultyAdjuster) GetNextDifficulty(
	currentFrameNumber uint64,
	currentTime int64,
) uint64 {
	args := m.Called(currentFrameNumber, currentTime)
	return args.Get(0).(uint64)
}
