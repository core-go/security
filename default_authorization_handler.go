package security

import "net/http"

type DefaultAuthorizer struct {
	PrivilegeService PrivilegeService
	Exact            bool
}

func NewAuthorizer(privilegeService PrivilegeService, exact bool) *DefaultAuthorizer {
	return &DefaultAuthorizer{PrivilegeService: privilegeService, Exact: exact}
}

func (h *DefaultAuthorizer) Authorize(next http.Handler, privilegeId string, action int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := GetUserIdFromContext(r)
		if len(userId) == 0 {
			http.Error(w, "Invalid User Id", http.StatusBadRequest)
			return
		}
		p := h.PrivilegeService.GetPrivilege(r.Context(), userId, privilegeId)
		if p == ActionNone {
			http.Error(w, "No Permission for this user", http.StatusForbidden)
			return
		}
		if action == ActionNone || action == ActionAll {
			next.ServeHTTP(w, r)
			return
		}
		sum := action & p
		if h.Exact {
			if sum == action {
				next.ServeHTTP(w, r)
				return
			}
		} else if sum >= action {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "No Permission", http.StatusForbidden)
	})
}

func GetUserIdFromContext(r *http.Request) string {
	token := r.Context().Value(Authorization)
	if token != nil {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			return GetUserId(authorizationToken)
		}
	}
	return ""
}
