package safe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTextRemovesTerminalControls(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"CSI", "safe\x1b[31mred\x1b[0m", "safered"},
		{"OSC BEL", "a\x1b]0;secret\x07b", "ab"},
		{"OSC ST", "a\x1b]8;;https://evil.invalid\x1b\\link\x1b]8;;\x1b\\b", "alinkb"},
		{"C1 CSI", "a\u009b31mred", "ared"},
		{"C1 OSC", "a\u009dtitle\u009cb", "ab"},
		{"DCS", "a\x1bPpayload\x1b\\b", "ab"},
		{"controls", "a\x00\t\r\n\x7fb", "ab"},
		{"bidi", "a\u061c\u202e\u2066b", "ab"},
		{"invalid UTF-8", string([]byte{'a', 0xff, 'b'}), "ab"},
		{"unterminated OSC", "a\x1b]hidden", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Text(tt.input); got != tt.want {
				t.Fatalf("Text(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTextLimitsLengthAndKeepsValidUTF8(t *testing.T) {
	got := Text(strings.Repeat("界", maxOutputRunes+100))
	if !utf8.ValidString(got) {
		t.Fatal("result is invalid UTF-8")
	}
	if utf8.RuneCountInString(got) != maxOutputRunes+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("unexpected truncated result length=%d suffix=%q", utf8.RuneCountInString(got), got[len(got)-3:])
	}
}
