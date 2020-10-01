package security

import (
	"net/http"
	"sort"
)

type DefaultUserAuthorizer struct {
	sortedUsers bool
}

func NewUserAuthorizer(sortedUsers bool) *DefaultUserAuthorizer {
	return &DefaultUserAuthorizer{sortedUsers}
}

func (h *DefaultUserAuthorizer) Authorize(next http.Handler, users []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := GetUserIdFromContext(r)
		if len(userId) == 0 {
			http.Error(w, "Invalid User Id", http.StatusBadRequest)
			return
		}
		if len(users) == 0 {
			http.Error(w, "No Permission", http.StatusForbidden)
			return
		}
		if h.sortedUsers {
			if HasSortedUser(userId, users) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if HasUser(userId, users) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "No Permission", http.StatusForbidden)
	})
}

func HasUser(currentUser string, users []string) bool {
	for _, user := range users {
		if user == currentUser {
			return true
		}
	}
	return false
}

func HasSortedUser(currentUser string, users []string) bool {
	i := sort.SearchStrings(users, currentUser)
	if i >= 0 && users[i] == currentUser {
		return true
	}
	return false
}
