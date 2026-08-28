// Package textutils provides shared text-processing helpers.
package textutils

import (
	"regexp"
	"strings"
)

// previously used regex from https://github.com/acarl005/stripansi
// "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

// ported from https://github.com/chalk/ansi-regex
const ansiRegexStr = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-nq-uy=><~]))"

var ansiRegex = regexp.MustCompile(ansiRegexStr)

// StripANSI removes ANSI escape sequences from str.
func StripANSI(str string) string {
	// skip when no escape sequences are in str
	if strings.IndexByte(str, 0x1b) == -1 && strings.IndexByte(str, 0x9b) == -1 {
		return str
	}
	return ansiRegex.ReplaceAllString(str, "")
}
