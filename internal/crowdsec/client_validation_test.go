package crowdsec

import (
	"testing"
)

func TestValidateComment(t *testing.T) {
	cases := []struct {
		name    string
		comment string
		wantErr bool
	}{
		{"empty allowed", "", false},
		{"normal text", "automated ban by security-automation", false},
		{"special chars", "ban: high-risk IP (score=95%)", false},
		{"null byte", "bad\x00comment", true},
		{"newline", "line1\nline2", true},
		{"carriage return", "line1\rline2", true},
		{"tab", "tab\there", true},
		{"delete char", "del\x7fchar", true},
		{"control char", "ctrl\x01char", true},
		{"invalid utf8", "bad\x80utf8", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateComment(tc.comment)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateComment(%q) error=%v, wantErr=%v", tc.comment, err, tc.wantErr)
			}
		})
	}
}
