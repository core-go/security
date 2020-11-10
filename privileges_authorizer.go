package security

import "net/http"

type PrivilegesAuthorizer struct {
	Authorization    string
	Key              string
	sortedPrivilege  bool
	exact            bool
	privilegesLoader PrivilegesLoader
}

func NewPrivilegesAuthorizer(authorization, key string, sortedPrivilege bool, exact bool, privilegesService PrivilegesLoader) *PrivilegesAuthorizer {
	return &PrivilegesAuthorizer{Authorization: authorization, Key: key, sortedPrivilege: sortedPrivilege, exact: exact, privilegesLoader: privilegesService}
}


func (h *PrivilegesAuthorizer) Authorize(next http.Handler, privilegeId string, action int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := ValueFromContext(r, h.Authorization, h.Key)
		if len(userId) == 0 {
			http.Error(w, "Invalid User Id", http.StatusForbidden)
			return
		}
		privileges := h.privilegesLoader.Privileges(r.Context(), userId)
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
