package security

import (
	"net/http"
	"sort"
)

type DefaultRoleAuthorizationHandler struct {
	sortedRoles bool
}

func NewRoleAuthorizationHandler(sortedRoles bool) *DefaultRoleAuthorizationHandler {
	return &DefaultRoleAuthorizationHandler{sortedRoles}
}

func (h *DefaultRoleAuthorizationHandler) Authorize(next http.Handler, roles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userRoles := h.getRolesFromContext(r)
		if userRoles == nil || len(*userRoles) == 0 {
			http.Error(w, "No Permission: Require roles for this user", http.StatusForbidden)
			return
		}
		if h.sortedRoles {
			if h.hasSortedRole(roles, *userRoles) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if h.hasRole(roles, *userRoles) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "No Permission", http.StatusForbidden)
	})
}

func (h *DefaultRoleAuthorizationHandler) hasRole(roles []string, userRoles []string) bool {
	for _, role := range roles {
		for _, userRole := range userRoles {
			if role == userRole {
				return true
			}
		}
	}
	return false
}

func (h *DefaultRoleAuthorizationHandler) hasSortedRole(roles []string, userRoles []string) bool {
	for _, role := range roles {
		i := sort.SearchStrings(userRoles, role)
		if i >= 0 && userRoles[i] == role {
			return true
		}
	}
	return false
}

func (h *DefaultRoleAuthorizationHandler) getRolesFromContext(r *http.Request) *[]string {
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
