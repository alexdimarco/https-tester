package nginxreview

import "testing"

// FuzzAnalyze checks the lexer and the static review never panic on arbitrary
// pasted text (operators paste messy config and log output).
func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{
		"server { ssl_protocols TLSv1.2; }",
		"ssl_ecdh_curve prime256v1:secp256r1;",
		"# comment\n\"unterminated",
		"} } {", "ssl_ciphers 'TLS_AES_128_GCM_SHA256';",
		"nginx: [emerg] boom", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = lex(s)
		_ = Analyze(s) // must not panic; result shape is not asserted
	})
}
