package security

import "net/http"

type UserAuthorizationHandler interface {
	Authorize(next http.Handler, users []string) http.Handler
}
