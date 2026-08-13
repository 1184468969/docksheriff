// Package safe contains output-boundary helpers for untrusted text.
package safe

import (
	"strings"
	"unicode/utf8"
)

const (
	maxInputBytes  = 4096
	maxOutputRunes = 256
)

// Text removes terminal control sequences, control and bidi characters,
// invalid UTF-8, and excessive length from an untrusted value.
func Text(value string) string {
	if len(value) > maxInputBytes {
		value = value[:maxInputBytes]
	}
	value = strings.ToValidUTF8(value, "")

	var out strings.Builder
	out.Grow(min(len(value), maxOutputRunes))
	state := stateText
	count := 0
	truncated := false

	for _, r := range value {
		switch state {
		case stateEscape:
			switch r {
			case '[':
				state = stateCSI
			case ']':
				state = stateOSC
			case 'P', 'X', '^', '_':
				state = stateString
			default:
				state = stateText
			}
			continue
		case stateCSI:
			if r >= 0x40 && r <= 0x7e {
				state = stateText
			} else if r == 0x1b {
				state = stateEscape
			}
			continue
		case stateOSC, stateString:
			switch r {
			case 0x07, 0x9c:
				state = stateText
			case 0x1b:
				if state == stateOSC {
					state = stateOSCEscape
				} else {
					state = stateStringEscape
				}
			}
			continue
		case stateOSCEscape, stateStringEscape:
			if r == '\\' {
				state = stateText
			} else if state == stateOSCEscape {
				state = stateOSC
			} else {
				state = stateString
			}
			continue
		}

		switch {
		case r == 0x1b:
			state = stateEscape
		case r == 0x9b:
			state = stateCSI
		case r == 0x9d:
			state = stateOSC
		case r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f:
			state = stateString
		case isControl(r) || isBidiControl(r):
			continue
		default:
			if count == maxOutputRunes {
				truncated = true
				continue
			}
			out.WriteRune(r)
			count++
		}
	}
	if truncated {
		out.WriteRune('…')
	}
	return out.String()
}

func isControl(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == utf8.RuneError
}

func isBidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

type parserState uint8

const (
	stateText parserState = iota
	stateEscape
	stateCSI
	stateOSC
	stateOSCEscape
	stateString
	stateStringEscape
)
