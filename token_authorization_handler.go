package security

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type TokenAuthorizationHandler struct {
	sortedPrivilege bool
	exact           bool
}

func NewTokenAuthorizationHandler(sortedPrivilege bool, exact bool) *TokenAuthorizationHandler {
	return &TokenAuthorizationHandler{sortedPrivilege, exact}
}

func (h *TokenAuthorizationHandler) Authorize(next http.Handler, privilegeId string, action int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privileges := h.getPrivilegesFromContext(r)
		if privileges == nil || len(privileges) == 0 {
			http.Error(w, "No Permission: Require privileges for this user", http.StatusForbidden)
			return
		}

		privilegeAction := h.getAction(privileges, privilegeId)
		if privilegeAction == ActionNone {
			http.Error(w, "No Permission for this user", http.StatusForbidden)
			return
		}
		if action == ActionNone || action == ActionAll {
			next.ServeHTTP(w, r)
			return
		}
		sum := action & privilegeAction
		if h.exact {
			if sum == action {
				next.ServeHTTP(w, r)
				return
			}
		} else {
			if sum >= action {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "No Permission", http.StatusForbidden)
	})
}

func (h *TokenAuthorizationHandler) getPrivilegesFromContext(r *http.Request) []string {
	token := r.Context().Value(Authorization)
	privileges := make([]string, 0)
	if authorizationToken, ok1 := token.(map[string]interface{}); ok1 {
		pPrivileges, ok2 := authorizationToken["privileges"]
		if !ok2 || pPrivileges == nil {
			return privileges
		}
		if rawPrivileges, ok3 := pPrivileges.([]interface{}); ok3 {
			for _, rawPrivilege := range rawPrivileges {
				if s, ok4 := rawPrivilege.(string); ok4 {
					privileges = append(privileges, s)
				}
			}
		}
	}
	return privileges
}

func (h *TokenAuthorizationHandler) getIndexPrivilegeFromSortedPrivileges(privileges []string, privilegeId string) int {
	return sort.Search(len(privileges), func(i int) bool { return privileges[i][:strings.Index(privileges[i], ":")] >= privilegeId })
}

func (h *TokenAuthorizationHandler) getAction(privileges []string, privilegeId string) int32 {
	prefix := fmt.Sprintf("%s:", privilegeId)
	prefixLen := len(prefix)

	if h.sortedPrivilege {
		i := h.getIndexPrivilegeFromSortedPrivileges(privileges, privilegeId)
		if i >= 0 && i < len(privileges) && strings.HasPrefix(privileges[i], prefix) {
			hexAction := privileges[i][prefixLen:]
			if action, err := h.convertHexAction(hexAction); err == nil {
				return action
			}
		}
	} else {
		for _, privilege := range privileges {
			if strings.HasPrefix(privilege, prefix) {
				hexAction := privilege[prefixLen:]
				if action, err := h.convertHexAction(hexAction); err == nil {
					return action
				}
			}
		}
	}

	return ActionNone
}

func (h *TokenAuthorizationHandler) convertHexAction(hexAction string) (int32, error) {
	if action64, err := strconv.ParseInt(hexAction, 16, 64); err == nil {
		return int32(action64), nil
	} else {
		return 0, err
	}
}
