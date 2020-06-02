package security

import "net/http"

type AuthorizationHandler interface {
	Authorize(next http.Handler, privilege string, action int32) http.Handler
}
