package security

import "net/http"

type SubAuthorizer interface {
	Authorize(next http.Handler, privilege string, sub string, action int32) http.Handler
}
