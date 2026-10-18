// Package nginxreview statically reviews operator-supplied Nginx configuration
// text. It never connects to a server, never executes anything, and never opens
// include paths referenced by the text. A static review is not a substitute for
// "nginx -t" against the actual running instance; it is a reading of pasted
// text, and it says so.
package nginxreview

import (
	"strings"
)

// Register labels where this evidence came from.
const Register = "operator_supplied_static_review"

// Severity mirrors the assessment vocabulary; no aggregate score.
const (
	SeverityInfo      = "info"
	SeverityConsider  = "consider"
	SeverityAttention = "attention"
)

// Review is the structured result of reading a configuration excerpt.
type Review struct {
	Register    string    `json:"register"`
	Findings    []Finding `json:"findings"`
	Notes       []string  `json:"notes"`
	ParseErrors []string  `json:"parse_errors"`
}

// Finding is one observation about the configuration text.
type Finding struct {
	Topic    string `json:"topic"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// directive is one parsed statement: a name plus its arguments.
type directive struct {
	name string
	args []string
}

// Analyze lexes the text and returns a static review.
func Analyze(text string) Review {
	r := Review{Register: Register}
	dirs, perrs := lex(text)
	r.ParseErrors = perrs

	var protocols, curves []string
	var ciphers []string
	var confCommandSuites []string
	hasInclude := false
	defaultServer := false

	for _, d := range dirs {
		switch d.name {
		case "ssl_protocols":
			protocols = append(protocols, d.args...)
		case "ssl_ecdh_curve":
			for _, a := range d.args {
				curves = append(curves, splitCurveArg(a)...)
			}
		case "ssl_ciphers":
			ciphers = append(ciphers, d.args...)
		case "ssl_conf_command":
			if len(d.args) == 2 && strings.EqualFold(d.args[0], "Ciphersuites") {
				confCommandSuites = append(confCommandSuites, d.args[1])
			}
		case "include":
			hasInclude = true
		case "listen":
			for _, a := range d.args {
				if a == "default_server" {
					defaultServer = true
				}
			}
		}
	}

	r.Findings = append(r.Findings, protocolFindings(protocols)...)
	r.Findings = append(r.Findings, curveFindings(curves)...)
	r.Findings = append(r.Findings, cipherPlacementFindings(ciphers, confCommandSuites)...)
	if defaultServer {
		r.Findings = append(r.Findings, Finding{
			Topic: "Default server", Severity: SeverityInfo,
			Detail: "A listen directive marks a default_server. A no-SNI or unexpected-host connection is served by this block; confirm it is the block you intend to test.",
		})
	}
	r.Findings = append(r.Findings, reloadFindings(text)...)

	// Caveats that always apply to a static read.
	r.Notes = append(r.Notes,
		"This is a static reading of pasted text, not the running configuration. Confirm with 'nginx -t' and 'nginx -T' on the actual instance.",
		"Alias spelling is retained as written; semantic normalization is shown separately.",
	)
	if hasInclude {
		r.Notes = append(r.Notes, "The configuration references include files, which were NOT opened. The effective configuration may differ from this excerpt.")
	}
	if len(dirs) == 0 {
		r.Notes = append(r.Notes, "No directives were recognized. Paste an ssl-related excerpt of the server/http block.")
	}
	return r
}

func protocolFindings(protocols []string) []Finding {
	if len(protocols) == 0 {
		return nil
	}
	var weak []string
	for _, p := range protocols {
		switch p {
		case "TLSv1", "TLSv1.1", "SSLv2", "SSLv3":
			weak = append(weak, p)
		}
	}
	if len(weak) > 0 {
		return []Finding{{
			Topic: "TLS protocols", Severity: SeverityAttention,
			Detail: "ssl_protocols enables " + strings.Join(protocols, " ") + ". " + strings.Join(weak, ", ") +
				" are weak and formally deprecated (IETF RFC 8996 / BCP 195); remove them so only TLS 1.2 and TLS 1.3 remain.",
		}}
	}
	return []Finding{{
		Topic: "TLS protocols", Severity: SeverityInfo,
		Detail: "ssl_protocols enables " + strings.Join(protocols, " ") + ", which avoids the deprecated legacy versions.",
	}}
}

// curveAliases maps known spellings to their canonical group name.
var curveAliases = map[string]string{
	"prime256v1": "P-256", "secp256r1": "P-256", "P-256": "P-256",
	"secp384r1": "P-384", "P-384": "P-384",
	"secp521r1": "P-521", "P-521": "P-521",
	"X25519": "X25519", "x25519": "X25519",
	"X448": "X448", "x448": "X448",
}

func curveFindings(curves []string) []Finding {
	if len(curves) == 0 {
		return nil
	}
	canonCount := map[string][]string{}
	var unknown []string
	for _, c := range curves {
		if c == "" || strings.EqualFold(c, "auto") {
			continue
		}
		if canon, ok := curveAliases[c]; ok {
			canonCount[canon] = append(canonCount[canon], c)
		} else {
			unknown = append(unknown, c)
		}
	}
	var out []Finding
	normalized := make([]string, 0, len(canonCount))
	for canon, spellings := range canonCount {
		normalized = append(normalized, canon)
		if len(spellings) > 1 {
			out = append(out, Finding{
				Topic: "Duplicate key-exchange group alias", Severity: SeverityConsider,
				Detail: "ssl_ecdh_curve lists " + strings.Join(spellings, " and ") + ", which are the SAME group (" + canon +
					"), not additional capabilities. Whether a build accepts the duplicate is version-dependent; confirm with 'nginx -t' against the linked TLS library.",
			})
		}
	}
	out = append([]Finding{{
		Topic: "Key-exchange groups (ssl_ecdh_curve)", Severity: SeverityInfo,
		Detail: "Configured groups (as written): " + strings.Join(curves, " ") + ". Normalized: " + strings.Join(normalized, ", ") + ".",
	}}, out...)
	if len(unknown) > 0 {
		out = append(out, Finding{
			Topic: "Unrecognized group token", Severity: SeverityConsider,
			Detail: "These tokens were not recognized as known groups: " + strings.Join(unknown, ", ") + ". They may be library-specific or typos; confirm against the linked TLS library.",
		})
	}
	return out
}

func cipherPlacementFindings(ciphers, confCommandSuites []string) []Finding {
	var out []Finding
	joined := strings.Join(ciphers, ":")
	if strings.Contains(joined, "TLS_") {
		out = append(out, Finding{
			Topic: "TLS 1.3 suite names in ssl_ciphers", Severity: SeverityAttention,
			Detail: "ssl_ciphers appears to contain TLS 1.3 suite names (TLS_*). ssl_ciphers governs TLS 1.2 and below; TLS 1.3 suites are set with 'ssl_conf_command Ciphersuites ...'. The TLS_* names here likely have no effect.",
		})
	}
	if len(confCommandSuites) > 0 {
		out = append(out, Finding{
			Topic: "TLS 1.3 cipher suites", Severity: SeverityInfo,
			Detail: "ssl_conf_command Ciphersuites is set to " + strings.Join(confCommandSuites, " ") + " (the correct place for TLS 1.3 suites).",
		})
	}
	return out
}

func reloadFindings(text string) []Finding {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "[emerg]"), strings.Contains(lower, "test failed"):
		return []Finding{{
			Topic: "Reload / config test", Severity: SeverityAttention,
			Detail: "The pasted output contains an error ([emerg] or \"test failed\"). A rejected reload means Nginx keeps serving its PREVIOUS configuration — the file may not describe the running process. Fix the exact error and confirm a successful reload.",
		}}
	case strings.Contains(lower, "test is successful"):
		return []Finding{{
			Topic: "Reload / config test", Severity: SeverityInfo,
			Detail: "The pasted output reports \"test is successful\". Confirm the reload was actually applied (a successful test is not the same as a reloaded process).",
		}}
	default:
		return nil
	}
}

// splitCurveArg splits an ssl_ecdh_curve argument, which may be colon-separated.
func splitCurveArg(a string) []string {
	parts := strings.Split(a, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
