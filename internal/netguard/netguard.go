// Package netguard makes outbound requests to caller-supplied URLs safe.
//
// Webhook targets are chosen by tenants, and our workers run inside a trusted
// network. Without these checks a tenant could point a webhook at the cloud
// metadata service or an internal database and have us fetch it for them.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	ErrBlockedAddress = errors.New("destination address is not permitted")
	ErrBlockedScheme  = errors.New("only http and https destinations are permitted")
	ErrBlockedPort    = errors.New("only ports 80 and 443 are permitted")
	ErrTooManyHops    = errors.New("too many redirects")
)

// IsBlocked reports addresses that must never be dialled. Checking the
// resolved IP rather than the hostname is the point: a name under the caller's
// control can resolve anywhere, including back into our own network.
func IsBlocked(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsUnspecified():
		return true
	}

	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 127, b[0] == 0, b[0] == 10:
			return true
		case b[0] == 169 && b[1] == 254: // link-local, includes cloud metadata
			return true
		case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
			return true
		case b[0] == 192 && b[1] == 168:
			return true
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // carrier-grade NAT
			return true
		case b[0] == 192 && b[1] == 0 && b[2] == 0: // IETF protocol assignments
			return true
		case b[0] >= 240: // reserved, includes broadcast
			return true
		}
		return false
	}

	if addr.Is6() {
		b := addr.As16()
		switch {
		case b[0] == 0xfc, b[0] == 0xfd: // unique local
			return true
		case b[0] == 0xfe && b[1]&0xc0 == 0x80: // link-local
			return true
		case addr == netip.MustParseAddr("::1"):
			return true
		}
	}
	return false
}

// ValidateURL checks the parts that do not require a lookup.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("destination is not a valid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrBlockedScheme
	}
	if u.Host == "" {
		return nil, errors.New("destination is missing a host")
	}
	switch port := u.Port(); port {
	case "", "80", "443":
	default:
		return nil, ErrBlockedPort
	}
	// A bare IP destination is checked immediately; names are checked at dial
	// time, after resolution.
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil && IsBlocked(addr) {
		return nil, ErrBlockedAddress
	}
	if strings.EqualFold(host, "localhost") {
		return nil, ErrBlockedAddress
	}
	return u, nil
}

// Client returns an HTTP client that validates the address it actually
// connects to. Checking a hostname and then handing it to the dialler leaves a
// window where DNS can answer differently the second time, so validation
// happens on the resolved address inside the dial itself.
func Client(timeout time.Duration, maxRedirects int) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("resolving %s: %w", host, err)
			}
			for _, ip := range ips {
				if IsBlocked(ip) {
					return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlockedAddress, host, ip)
				}
			}
			// Dial the address that was checked, not the name.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		MaxIdleConns:          4,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrTooManyHops
			}
			// Every hop is a fresh destination chosen by the far end, so each
			// one is validated again rather than trusted because the first was.
			if _, err := ValidateURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}
