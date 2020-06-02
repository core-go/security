package security

import "net/http"

type DefaultUserTypeAuthorizationHandler struct {
}

func NewUserTypeAuthorizationHandler() *DefaultUserTypeAuthorizationHandler {
	return &DefaultUserTypeAuthorizationHandler{}
}

func (h *DefaultUserTypeAuthorizationHandler) Authorize(next http.Handler, userTypes []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userType := h.getUserTypeFromContext(r)
		if userType == nil || len(*userType) == 0 {
			http.Error(w, "No Permission: Require User Type", http.StatusForbidden)
			return
		}
		if h.hasUserType(userTypes, *userType) {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "No Permission", http.StatusForbidden)
		}
	})
}

func (h *DefaultUserTypeAuthorizationHandler) hasUserType(userTypes []string, userType string) bool {
	for _, rt := range userTypes {
		if rt == userType {
			return true
		}
	}
	return false
}

func (h *DefaultUserTypeAuthorizationHandler) getUserTypeFromContext(r *http.Request) *string {
	token := r.Context().Value(Authorization)
	if token != nil {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			t := GetUserType(authorizationToken)
			return &t
		}
	}
	return nil
}
