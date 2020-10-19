package security

type TokenWhitelistChecker interface {
	Check(id string, token string) bool
}
