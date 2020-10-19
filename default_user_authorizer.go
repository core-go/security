package security

import (
	"net/http"
)

type DefaultUserAuthorizer struct {
	Authorization string
	Key           string
	sortedUsers   bool
}

func NewUserAuthorizer(authorization string, key string, sortedUsers bool) *DefaultUserAuthorizer {
	return &DefaultUserAuthorizer{Authorization: authorization, Key: key, sortedUsers: sortedUsers}
}

func (h *DefaultUserAuthorizer) Authorize(next http.Handler, users []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ValueFromContext(r, h.Authorization, h.Key)
		if len(user) == 0 {
			http.Error(w, "Invalid User Id", http.StatusBadRequest)
			return
		}
		if len(users) == 0 {
			http.Error(w, "No Permission", http.StatusForbidden)
			return
		}
		if h.sortedUsers {
			if IncludeOfSort(users, user) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if Include(users, user) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "No Permission", http.StatusForbidden)
	})
}
