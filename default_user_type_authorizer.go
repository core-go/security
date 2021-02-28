package security

import "net/http"

type DefaultUserTypeAuthorizer struct {
	Authorization string
	Key           string
}

func NewUserTypeAuthorizer(options ...string) *DefaultUserTypeAuthorizer {
	authorization := ""
	key := "userType"
	if len(options) >= 2 {
		authorization = options[1]
	}
	if len(options) >= 1 {
		key = options[0]
	}
	return &DefaultUserTypeAuthorizer{Authorization: authorization, Key: key}
}

func (h *DefaultUserTypeAuthorizer) Authorize(next http.Handler, userTypes []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userType := FromContext(r, h.Authorization, h.Key)
		if userType == nil || len(*userType) == 0 {
			http.Error(w, "No permission: Require User Type", http.StatusForbidden)
			return
		}
		if Include(userTypes, *userType) {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "No permission", http.StatusForbidden)
		}
	})
}
