package security

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const Authorization = "authorization"

type DefaultAuthenticationHandler struct {
	TokenBlacklistService TokenBlacklistService
	TokenVerifier         TokenVerifier
	Secret                string
}

func NewAuthenticationHandler(tokenBlacklistService TokenBlacklistService, tokenVerifier TokenVerifier, secret string) *DefaultAuthenticationHandler {
	return &DefaultAuthenticationHandler{TokenBlacklistService: tokenBlacklistService, TokenVerifier: tokenVerifier, Secret: secret}
}

func (h *DefaultAuthenticationHandler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := r.Header["Authorization"]
		if len(data) == 0 {
			http.Error(w, "'Authorization' is required in http request header.", http.StatusUnauthorized)
			return
		}
		authorization := data[0]
		if strings.HasPrefix(authorization, "Bearer ") != true {
			http.Error(w, "Invalid 'Authorization' format. The format must be 'Authorization: Bearer [token]'", http.StatusUnauthorized)
			return
		}
		token := authorization[7:]
		if data, issuedAt, _, err := h.TokenVerifier.VerifyToken(token, h.Secret); err != nil {
			http.Error(w, "Invalid Authorization Token", http.StatusUnauthorized)
		} else {
			iat := time.Unix(issuedAt, 0)
			data["token"] = token
			data["issuedAt"] = iat
			if h.TokenBlacklistService != nil {
				if data != nil {
					userId := GetUserId(data)
					reason := h.TokenBlacklistService.Check(userId, token, iat)
					if len(reason) == 0 {
						ctx := context.WithValue(r.Context(), Authorization, data)
						next.ServeHTTP(w, r.WithContext(ctx))
					} else {
						http.Error(w, "Token is not valid anymore", http.StatusUnauthorized)
					}
				} else {
					ctx := context.WithValue(r.Context(), Authorization, data)
					next.ServeHTTP(w, r.WithContext(ctx))
				}
			} else {
				ctx := context.WithValue(r.Context(), Authorization, data)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		}
	})
}
