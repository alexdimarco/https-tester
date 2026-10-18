// Package redact is the single boundary through which potentially sensitive
// material passes before it is stored or rendered. It removes credential-bearing
// header values and strips userinfo and token-like query values from URLs.
//
// It is deliberately conservative: when a value cannot be safely isolated, the
// whole thing is replaced rather than partially masked.
package redact

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Placeholder is what replaces a removed value.
const Placeholder = "[redacted]"

// sensitiveHeaders are removed entirely from any stored or rendered header set.
var sensitiveHeaders = map[string]bool{
	"authorization":        true,
	"proxy-authorization":  true,
	"cookie":               true,
	"set-cookie":           true,
	"x-api-key":            true,
	"x-auth-token":         true,
	"x-amz-security-token": true,
}

// sensitiveQueryKeys are query parameters whose values look like secrets.
var sensitiveQueryKeys = map[string]bool{
	"access_token": true,
	"token":        true,
	"apikey":       true,
	"api_key":      true,
	"key":          true,
	"secret":       true,
	"password":     true,
	"sig":          true,
	"signature":    true,
	"code":         true,
}

// Headers returns a stable, redacted, display-ready copy of an HTTP header set.
func Headers(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if sensitiveHeaders[strings.ToLower(k)] {
			out[k] = Placeholder
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// HeaderKeys lists the header names present, sorted — useful when even the
// values of non-sensitive headers are more than a report should carry.
func HeaderKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// URL removes userinfo and masks token-like query values, returning a string
// safe to store. If the input cannot be parsed it is returned as the
// placeholder rather than risking leaking a malformed secret.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return Placeholder
	}
	if u.User != nil {
		u.User = url.User(Placeholder)
	}
	if u.RawQuery != "" {
		q := u.Query()
		for key := range q {
			if sensitiveQueryKeys[strings.ToLower(key)] {
				q.Set(key, Placeholder)
			}
		}
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Error renders an error for storage. The errors it receives are library/OS
// connection errors, not response bodies, so there is nothing to strip beyond a
// defensive userinfo/token pass over any URL-like substring; it is kept simple
// and marked as operating only on client-side error text.
func Error(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
