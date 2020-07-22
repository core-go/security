package security

import (
	"net/http"
	"sort"
)

type DefaultUserAuthorizationHandler struct {
	sortedUsers bool
}

func NewUserAuthorizationHandler(sortedUsers bool) *DefaultUserAuthorizationHandler {
	return &DefaultUserAuthorizationHandler{sortedUsers}
}

func (h *DefaultUserAuthorizationHandler) Authorize(next http.Handler, users []string) http.Handler {
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
			if h.hasSortedUser(userId, users) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if h.hasUser(userId, users) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "No Permission", http.StatusForbidden)
	})
}

func (h *DefaultUserAuthorizationHandler) hasUser(currentUser string, users []string) bool {
	for _, user := range users {
		if user == currentUser {
			return true
		}
	}
	return false
}

func (h *DefaultUserAuthorizationHandler) hasSortedUser(currentUser string, users []string) bool {
	i := sort.SearchStrings(users, currentUser)
	if i >= 0 && users[i] == currentUser {
		return true
	}
	return false
}
