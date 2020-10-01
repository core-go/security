package security

import (
	"net/http"
	"sort"
)

type DefaultRoleAuthorizer struct {
	sortedRoles bool
}

func NewRoleAuthorizer(sortedRoles bool) *DefaultRoleAuthorizer {
	return &DefaultRoleAuthorizer{sortedRoles}
}

func (h *DefaultRoleAuthorizer) Authorize(next http.Handler, roles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userRoles := GetRolesFromContext(r)
		if userRoles == nil || len(*userRoles) == 0 {
			http.Error(w, "No Permission: Require roles for this user", http.StatusForbidden)
			return
		}
		if h.sortedRoles {
			if HasSortedRole(roles, *userRoles) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if HasRole(roles, *userRoles) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "No Permission", http.StatusForbidden)
	})
}

func GetRolesFromContext(r *http.Request) *[]string {
	token := r.Context().Value(Authorization)
	if token != nil {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			pRoles, ok2 := authorizationToken["roles"]
			if !ok2 || pRoles == nil {
				return nil
			}
			if roles, exist := pRoles.(*[]string); exist {
				return roles
			}
		}
	}
	return nil
}

func HasRole(roles []string, userRoles []string) bool {
	for _, role := range roles {
		for _, userRole := range userRoles {
			if role == userRole {
				return true
			}
		}
	}
	return false
}

func HasSortedRole(roles []string, userRoles []string) bool {
	for _, role := range roles {
		i := sort.SearchStrings(userRoles, role)
		if i >= 0 && userRoles[i] == role {
			return true
		}
	}
	return false
}