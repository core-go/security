package security

import "net/http"

type UserAuthorizer interface {
	Authorize(next http.Handler, users []string) http.Handler
}
