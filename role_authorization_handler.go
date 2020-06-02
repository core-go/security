package security

import "net/http"

type RoleAuthorizationHandler interface {
	Authorize(next http.Handler, roles []string) http.Handler
}
