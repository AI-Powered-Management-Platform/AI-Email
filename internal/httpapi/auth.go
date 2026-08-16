package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/keys"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

const authKey contextKey = "api_key"

const (
	ScopeEmailsSend  = "emails:send"
	ScopeEmailsRead  = "emails:read"
	ScopeDomainsRead = "domains:read"
)

func APIKeyFrom(ctx context.Context) *store.APIKey {
	if v, ok := ctx.Value(authKey).(*store.APIKey); ok {
		return v
	}
	return nil
}

// requireKey authenticates the caller. Every rejection returns the same
// message and status: telling a caller whether a key exists, expired, or was
// revoked helps an attacker sort stolen strings.
func (s *Server) requireKey(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, ok := bearerToken(r)
		if !ok {
			unauthorized(w, r)
			return
		}
		if err := keys.Parse(secret); err != nil {
			unauthorized(w, r)
			return
		}

		key, err := s.keys.APIKeyByHash(r.Context(), keys.Hash(secret))
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.log.Error("key lookup failed", "request_id", RequestIDFrom(r.Context()), "error", err)
			}
			unauthorized(w, r)
			return
		}
		if key.Revoked() || key.Expired(time.Now()) {
			unauthorized(w, r)
			return
		}
		if !key.HasScope(scope) {
			writeError(w, r, http.StatusForbidden, "insufficient_scope", "this key is not permitted to perform that action")
			return
		}

		s.recordKeyUse(r, key.ID)
		next(w, r.WithContext(context.WithValue(r.Context(), authKey, key)))
	}
}

// recordKeyUse never blocks the request it describes.
func (s *Server) recordKeyUse(r *http.Request, id int64) {
	addr := clientAddr(r)
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if err := s.keys.TouchAPIKey(ctx, id, addr); err != nil {
			s.log.Warn("recording key use failed", "error", err)
		}
	}()
}

func bearerToken(r *http.Request) (string, bool) {
	raw := r.Header.Get("Authorization")
	if raw == "" {
		return "", false
	}
	scheme, token, found := strings.Cut(raw, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

// clientAddr uses the socket address. Forwarded headers are attacker-supplied
// unless a trusted proxy is configured, and a wrong source ip is worse than
// none: it teaches the owner to trust a fiction.
func clientAddr(r *http.Request) netip.Addr {
	host := r.RemoteAddr
	if h, _, err := splitHostPort(host); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func splitHostPort(hostport string) (string, string, error) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return hostport, "", errors.New("no port")
	}
	host := strings.TrimSuffix(strings.TrimPrefix(hostport[:i], "["), "]")
	return host, hostport[i+1:], nil
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="aiemail"`)
	writeError(w, r, http.StatusUnauthorized, "unauthorized", "the API key is missing, invalid, or no longer usable")
}
