package security

import (
	"net/http"
)

type DefaultUserAuthorizer struct {
	Authorization string
	Key           string
	sortedUsers   bool
}

func NewUserAuthorizer(sortedUsers bool, options ...string) *DefaultUserAuthorizer {
	authorization := ""
	key := "userId"
	if len(options) >= 2 {
		authorization = options[1]
	}
	if len(options) >= 1 {
		key = options[0]
	}
	return &DefaultUserAuthorizer{sortedUsers: sortedUsers, Authorization: authorization, Key: key}
}

func (h *DefaultUserAuthorizer) Authorize(next http.Handler, users []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ValueFromContext(r, h.Authorization, h.Key)
		if len(user) == 0 {
			http.Error(w, "Invalid User Id in http request", http.StatusForbidden)
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
