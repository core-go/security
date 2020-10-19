package security

import "time"

type TokenBlacklistChecker interface {
	Check(id string, token string, createAt time.Time) string
}
