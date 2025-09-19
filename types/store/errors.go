package store

import "errors"

var (
	ErrNotFound    = errors.New("item not found")
	ErrInvalidData = errors.New("invalid data")
)
