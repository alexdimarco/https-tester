// Package target parses and validates the operator's HTTPS address and
// classifies resolved network addresses for scope control.
//
// Validation happens before any network action. The classifier is the basis of
// the workbench's request-forgery defenses: link-local (including cloud
// metadata), multicast, unspecified, and broadcast destinations are hard
// blocked; private and loopback destinations are a legitimate administrator use
// case but require explicit approval.
package target

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Target is a validated, normalized HTTPS destination.
type Target struct {
	InputURL  string
	Host      string // hostname, never an empty string after validation
	Port      string // numeric string, defaulted to "443"
	Path      string // defaulted to "/"
	Authority string // host:port
	IsIP      bool   // true when Host is a literal IP address
}

// ParseAndValidate normalizes raw input and rejects anything unsafe before the
// workbench touches the network. The error messages are plain and name the
// specific problem.
func ParseAndValidate(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("the address is empty")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("the address contains a control character")
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("the address is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		if u.Scheme == "" {
			return nil, fmt.Errorf("the address must start with https:// (no scheme was given)")
		}
		return nil, fmt.Errorf("only https:// addresses are supported (this one uses %q)", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("credentials embedded in the URL (the user:password@ part) are not allowed")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("the address has no host")
	}
	isIP := false
	if addr, perr := netip.ParseAddr(host); perr == nil {
		isIP = true
		_ = addr
	} else {
		for _, r := range host {
			if r > 0x7f {
				return nil, fmt.Errorf("non-ASCII hostnames are not supported in this build (international-domain handling is planned); use the ASCII/punycode form, e.g. xn--...")
			}
		}
		if !isPlausibleHostname(host) {
			return nil, fmt.Errorf("the host %q does not look like a valid hostname", host)
		}
	}

	port := u.Port()
	if port == "" {
		port = "443"
	} else {
		n, perr := strconv.Atoi(port)
		if perr != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("the port %q is not a number between 1 and 65535", port)
		}
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}

	return &Target{
		InputURL:  raw,
		Host:      host,
		Port:      port,
		Path:      path,
		Authority: net.JoinHostPort(host, port),
		IsIP:      isIP,
	}, nil
}

// RequestURL rebuilds a canonical https URL from the validated parts. The path
// is reused verbatim; query and fragment are dropped for the Gate A HEAD probe.
func (t *Target) RequestURL() string {
	return "https://" + t.Authority + t.Path
}

func isPlausibleHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}

// Class is the scope classification of a resolved address.
type Class int

const (
	// ClassPublic is an ordinary routable address: allowed.
	ClassPublic Class = iota
	// ClassPrivateOrLoopback is private (RFC 1918 / ULA) or loopback: a valid
	// admin target, but only with explicit approval.
	ClassPrivateOrLoopback
	// ClassBlocked must never be probed by this build.
	ClassBlocked
)

// Classify reports the scope class of an address and, when blocked, why.
func Classify(addr netip.Addr) (Class, string) {
	switch {
	case addr.IsUnspecified():
		return ClassBlocked, "unspecified address (0.0.0.0 / ::)"
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast(), addr.IsLinkLocalMulticast():
		return ClassBlocked, "multicast address"
	case addr.IsLinkLocalUnicast():
		return ClassBlocked, "link-local address (includes cloud metadata endpoints)"
	case isBroadcast(addr):
		return ClassBlocked, "broadcast address"
	case addr.IsLoopback(), addr.IsPrivate():
		return ClassPrivateOrLoopback, ""
	default:
		return ClassPublic, ""
	}
}

func isBroadcast(addr netip.Addr) bool {
	return addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
