package security

import "net/http"

type UserTypeAuthorizationHandler interface {
	Authorize(next http.Handler, userTypes []string) http.Handler
}
