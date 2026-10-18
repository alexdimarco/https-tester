package nginxreview

import "strings"

// lex performs a minimal, correct tokenization of Nginx configuration text. It
// understands line comments, single/double quoted arguments, braces, and
// semicolons — it does not rely on a single regular expression. It returns the
// flat list of directives plus any structural parse errors (unbalanced braces,
// an unterminated quote).
func lex(text string) ([]directive, []string) {
	var (
		dirs    []directive
		errs    []string
		pending []string // tokens collected for the current statement
		cur     strings.Builder
		inTok   bool
		quote   rune // 0, '"', or '\''
		depth   int
	)

	flushToken := func() {
		if inTok {
			pending = append(pending, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	finish := func() {
		flushToken()
		if len(pending) > 0 {
			dirs = append(dirs, directive{name: pending[0], args: pending[1:]})
		}
		pending = nil
	}

	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if quote != 0 {
			if c == quote {
				quote = 0
				flushToken()
			} else {
				inTok = true
				cur.WriteRune(c)
			}
			continue
		}

		switch c {
		case '#':
			// Comment: skip to end of line.
			flushToken()
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
		case '"', '\'':
			quote = c
			inTok = true // an empty quoted string is still a token
		case ';':
			finish()
		case '{':
			finish() // the tokens before '{' are the block header
			depth++
		case '}':
			flushToken()
			if len(pending) > 0 {
				finish()
			}
			depth--
			if depth < 0 {
				errs = append(errs, "unbalanced '}' (a closing brace with no matching open)")
				depth = 0
			}
		case ' ', '\t', '\r', '\n':
			flushToken()
		default:
			inTok = true
			cur.WriteRune(c)
		}
	}
	finish()

	if quote != 0 {
		errs = append(errs, "unterminated quoted string")
	}
	if depth > 0 {
		errs = append(errs, "unbalanced '{' (a block was not closed)")
	}
	return dirs, errs
}
