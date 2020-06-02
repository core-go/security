package security

import "net/http"

type DefaultAuthorizationHandler struct {
	PrivilegeService PrivilegeService
	Exact            bool
}

func NewAuthorizationHandler(privilegeService PrivilegeService, exact bool) *DefaultAuthorizationHandler {
	return &DefaultAuthorizationHandler{PrivilegeService: privilegeService, Exact: exact}
}

func (h *DefaultAuthorizationHandler) Authorize(next http.Handler, privilegeId string, action int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := h.getUserIdFromContext(r)
		if len(userId) == 0 {
			http.Error(w, "Invalid User Id", http.StatusBadRequest)
			return
		}
		p := h.PrivilegeService.GetPrivilege(userId, privilegeId)
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

func (h *DefaultAuthorizationHandler) getUserIdFromContext(r *http.Request) string {
	token := r.Context().Value(Authorization)
	if token != nil {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			return GetUserId(authorizationToken)
		}
	}
	return ""
}
