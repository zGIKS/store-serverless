package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func Middleware(jwtSecret string, next http.Handler) http.Handler {
	secret := []byte(jwtSecret)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if header == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeError(w, http.StatusUnauthorized, "invalid authorization format")
			return
		}

		tokenStr := strings.TrimSpace(parts[1])
		if tokenStr == "" {
			writeError(w, http.StatusUnauthorized, "invalid authorization token")
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
			return secret, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		if tokenType, _ := claims["typ"].(string); tokenType != "access" {
			writeError(w, http.StatusUnauthorized, "invalid token type")
			return
		}

		next.ServeHTTP(w, r)
	})
}
