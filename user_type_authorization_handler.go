package security

import "net/http"

type UserTypeAuthorizer interface {
	Authorize(next http.Handler, userTypes []string) http.Handler
}
