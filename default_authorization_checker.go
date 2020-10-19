package security

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const (
	Authorization = "authorization"
	UserId        = "userId"
	Username      = "username"
	UserType      = "userType"
	Roles         = "roles"
	Privileges    = "privileges"
	Ip            = "ip"
)

type DefaultAuthorizationChecker struct {
	Authorization         string
	Key                   string
	TokenBlacklistChecker TokenBlacklistChecker
	TokenVerifier         TokenVerifier
	Secret                string
	Ip                    string
	TokenWhitelistChecker TokenWhitelistChecker
}

func NewAuthorizationChecker(authorization, key string, tokenBlacklistService TokenBlacklistChecker, tokenVerifier TokenVerifier, secret string, tokenWhitelistChecker TokenWhitelistChecker) *DefaultAuthorizationChecker {
	return NewAuthorizationCheckerWithIp(authorization, key, tokenBlacklistService, tokenVerifier, secret, "", tokenWhitelistChecker)
}

func NewAuthorizationCheckerWithIp(authorization, key string, tokenBlacklistService TokenBlacklistChecker, tokenVerifier TokenVerifier, secret string, ip string, tokenWhitelistChecker TokenWhitelistChecker) *DefaultAuthorizationChecker {
	return &DefaultAuthorizationChecker{Authorization: authorization, Key: key, TokenBlacklistChecker: tokenBlacklistService, TokenVerifier: tokenVerifier, Secret: secret, Ip: ip, TokenWhitelistChecker: tokenWhitelistChecker}
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
		data, issuedAt, _, err := h.TokenVerifier.VerifyToken(token, h.Secret)
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
		if h.TokenBlacklistChecker != nil {
			user := ValueFromMap(h.Key, data)
			reason := h.TokenBlacklistChecker.Check(user, token, iat)
			if len(reason) > 0 {
				http.Error(w, "Token is not valid anymore", http.StatusUnauthorized)
			} else {
				if h.TokenWhitelistChecker != nil {
					valid := h.TokenWhitelistChecker.Check(user, token)
					if !valid {
						http.Error(w, "Token is not valid anymore", http.StatusUnauthorized)
						return
					}
				}
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
		} else {
			if h.TokenWhitelistChecker != nil {
				user := ValueFromMap(h.Key, data)
				valid := h.TokenWhitelistChecker.Check(user, token)
				if !valid {
					http.Error(w, "Token is not valid anymore", http.StatusUnauthorized)
					return
				}
			}
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
