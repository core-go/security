package security

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const (
	Authorization = "authorization"
	Uid           = "uid"
	UserId        = "userId"
	UserName      = "userName"
	Username      = "username"
	UserType      = "userType"
	Roles         = "roles"
	Privileges    = "privileges"
	Permission    = "permission"
	Permissions   = "permissions"
	Ip            = "ip"
)

type DefaultAuthorizationChecker struct {
	VerifyToken    func(tokenString string, secret string) (map[string]interface{}, int64, int64, error)
	Secret         string
	Ip             string
	CheckBlacklist func(id string, token string, createAt time.Time) string
	Authorization  string
	Key            string
	CheckWhitelist func(id string, token string) bool
}

func NewDefaultAuthorizationChecker(verifyToken func(string, string) (map[string]interface{}, int64, int64, error), secret string, key string, options ...string) *DefaultAuthorizationChecker {
	return NewAuthorizationCheckerWithIp(verifyToken, secret, "", nil, nil, key, options...)
}
func NewAuthorizationChecker(verifyToken func(string, string) (map[string]interface{}, int64, int64, error), secret string, checkToken func(string, string, time.Time) string, key string, options ...string) *DefaultAuthorizationChecker {
	return NewAuthorizationCheckerWithIp(verifyToken, secret, "", checkToken, nil, key, options...)
}
func NewAuthorizationCheckerWithWhitelist(verifyToken func(string, string) (map[string]interface{}, int64, int64, error), secret string, checkToken func(string, string, time.Time) string, checkWhitelist func(string, string) bool, key string, options ...string) *DefaultAuthorizationChecker {
	return NewAuthorizationCheckerWithIp(verifyToken, secret, "", checkToken, checkWhitelist, key, options...)
}
func NewAuthorizationCheckerWithIp(verifyToken func(string, string) (map[string]interface{}, int64, int64, error), secret string, ip string, checkToken func(string, string, time.Time) string, checkWhitelist func(string, string) bool, key string, options ...string) *DefaultAuthorizationChecker {
	var authorization string
	if len(options) >= 1 {
		authorization = options[0]
	}
	return &DefaultAuthorizationChecker{Authorization: authorization, Key: key, CheckBlacklist: checkToken, VerifyToken: verifyToken, Secret: secret, Ip: ip, CheckWhitelist: checkWhitelist}
}

func (h *DefaultAuthorizationChecker) Check(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au := r.Header["Authorization"]
		if len(au) == 0 {
			http.Error(w, "'Authorization' is required in http request header.", http.StatusUnauthorized)
			return
		}
		authorization := au[0]
		if strings.HasPrefix(authorization, "Bearer ") != true {
			http.Error(w, "Invalid 'Authorization' format. The format must be 'Authorization: Bearer [token]'", http.StatusUnauthorized)
			return
		}
		token := authorization[7:]
		data, issuedAt, _, err := h.VerifyToken(token, h.Secret)
		if err != nil {
			http.Error(w, "Invalid Authorization Token", http.StatusUnauthorized)
			return
		}
		if data == nil {
			data = make(map[string]interface{})
		}
		iat := time.Unix(issuedAt, 0)
		data["token"] = token
		data["issuedAt"] = iat
		var ctx context.Context
		ctx = r.Context()
		if len(h.Ip) > 0 {
			ip := GetRemoteIp(r)
			ctx = context.WithValue(ctx, h.Ip, ip)
		}
		if h.CheckBlacklist != nil {
			user := ValueFromMap(h.Key, data)
			reason := h.CheckBlacklist(user, token, iat)
			if len(reason) > 0 {
				http.Error(w, "Token is not valid anymore", http.StatusUnauthorized)
			} else {
				if h.CheckWhitelist != nil {
					valid := h.CheckWhitelist(user, token)
					if !valid {
						http.Error(w, "Token is not valid anymore", http.StatusUnauthorized)
						return
					}
				}
				if len(h.Authorization) > 0 {
					ctx := context.WithValue(ctx, h.Authorization, data)
					next.ServeHTTP(w, r.WithContext(ctx))
				} else {
					for k, e := range data {
						if len(k) > 0 {
							ctx = context.WithValue(ctx, k, e)
						}
					}
					next.ServeHTTP(w, r.WithContext(ctx))
				}
			}
		} else {
			if h.CheckWhitelist != nil {
				user := ValueFromMap(h.Key, data)
				valid := h.CheckWhitelist(user, token)
				if !valid {
					http.Error(w, "Token is not valid anymore", http.StatusUnauthorized)
					return
				}
			}
			if len(h.Authorization) > 0 {
				ctx := context.WithValue(ctx, h.Authorization, data)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				for k, e := range data {
					if len(k) > 0 {
						ctx = context.WithValue(ctx, k, e)
					}
				}
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		}
	})
}
func HandleAuthorization(ctx context.Context, next http.Handler, w http.ResponseWriter, r *http.Request, authorization string, data map[string]interface{}) {
	if len(authorization) > 0 {
		ctx := context.WithValue(ctx, authorization, data)
		next.ServeHTTP(w, r.WithContext(ctx))
	} else {
		for k, e := range data {
			if len(k) > 0 {
				ctx = context.WithValue(ctx, k, e)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
func ParseBearerToken(data []string) string {
	if len(data) == 0 {
		return ""
	}
	authorization := data[0]
	if strings.HasPrefix(authorization, "Bearer ") != true {
		return ""
	}
	return authorization[7:]
}
