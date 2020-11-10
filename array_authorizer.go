package security

import "net/http"

type ArrayAuthorizer interface {
	Authorize(next http.Handler, values []string) http.Handler
}
