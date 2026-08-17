package httpapi

import (
	"fmt"
	"net/http"
	"strings"
)

// MTA-STS lets a sending server discover that we require TLS, and refuse to
// deliver in clear if a downgrade is attempted. The policy is fetched over
// HTTPS from a fixed path, so serving it here is what makes the DNS record
// mean anything.
//
// Mode starts at testing rather than enforce: a policy that enforces before
// the certificate and hostnames are confirmed correct silently blocks real
// mail. An operator raises it once TLS reports show clean sessions.
func (s *Server) handleMTASTSPolicy(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.MTASTSHosts) == 0 {
		writeError(w, r, http.StatusNotFound, "not_found", "no policy is published")
		return
	}

	var b strings.Builder
	b.WriteString("version: STSv1\n")
	fmt.Fprintf(&b, "mode: %s\n", s.cfg.MTASTSMode)
	for _, host := range s.cfg.MTASTSHosts {
		fmt.Fprintf(&b, "mx: %s\n", host)
	}
	fmt.Fprintf(&b, "max_age: %d\n", s.cfg.MTASTSMaxAge)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(b.String()))
}

// security.txt tells a researcher where to report a flaw. Without it, the
// choice is a public issue or nothing, and a public issue is a disclosed
// vulnerability.
func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SecurityContact == "" {
		writeError(w, r, http.StatusNotFound, "not_found", "no security contact is published")
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Contact: %s\n", s.cfg.SecurityContact)
	if s.cfg.SecurityPolicyURL != "" {
		fmt.Fprintf(&b, "Policy: %s\n", s.cfg.SecurityPolicyURL)
	}
	b.WriteString("Preferred-Languages: en\n")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(b.String()))
}
