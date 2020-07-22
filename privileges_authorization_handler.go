package security

import "net/http"

type PrivilegesAuthorizationHandler struct {
	sortedPrivilege   bool
	exact             bool
	privilegesService PrivilegesService
}

func NewPrivilegesAuthorizationHandler(sortedPrivilege bool, exact bool, privilegesService PrivilegesService) *PrivilegesAuthorizationHandler {
	return &PrivilegesAuthorizationHandler{sortedPrivilege, exact, privilegesService}
}

func (h *PrivilegesAuthorizationHandler) Authorize(next http.Handler, privilegeId string, action int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := GetUserIdFromContext(r)
		if len(userId) == 0 {
			http.Error(w, "Invalid User Id", http.StatusBadRequest)
			return
		}
		privileges := h.privilegesService.GetPrivileges(r.Context(), userId)
		if privileges == nil || len(privileges) == 0 {
			http.Error(w, "No Permission: Require privileges for this user", http.StatusForbidden)
			return
		}

		privilegeAction := GetAction(privileges, privilegeId, h.sortedPrivilege)
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
