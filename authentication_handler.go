package security

import "net/http"

type AuthorizationChecker interface {
	Check(next http.Handler) http.Handler
}
