package security

import "net/http"

type DefaultSubAuthorizer struct {
	Authorization      string
	Key                string
	SubPrivilegeLoader SubPrivilegeLoader
	Exact              bool
}

func NewSubAuthorizer(subPrivilegeLoader SubPrivilegeLoader, exact bool) *DefaultSubAuthorizer {
	return &DefaultSubAuthorizer{SubPrivilegeLoader: subPrivilegeLoader, Exact: exact}
}

func (h *DefaultSubAuthorizer) Authorize(next http.Handler, privilegeId string, sub string, action int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := ValueFromContext(r, h.Authorization, h.Key)
		if len(userId) == 0 {
			http.Error(w, "Invalid User Id", http.StatusBadRequest)
			return
		}
		p := h.SubPrivilegeLoader.Privilege(r.Context(), userId, privilegeId, sub)
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
