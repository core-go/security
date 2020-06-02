package security

import "net/http"

type AuthenticationHandler interface {
	Authenticate(next http.Handler) http.Handler
}
