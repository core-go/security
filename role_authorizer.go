package security

import "net/http"

type RoleAuthorizer interface {
	Authorize(next http.Handler, roles []string) http.Handler
}
