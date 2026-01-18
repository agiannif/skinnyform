package main

import (
	"strings"
	"testing"
)

func TestValidateClientConfig(t *testing.T) {
	tests := []struct {
		name        string
		origins     []string
		emails      []string
		wantErr     bool
		errContains string
	}{
		{
			name:    "empty CLIENT_ORIGINS list returns error",
			origins: []string{},
			emails:  []string{"test@example.com"},
			wantErr: true,
		},
		{
			name:    "empty CLIENT_EMAILS list returns error",
			origins: []string{"https://example.com"},
			emails:  []string{},
			wantErr: true,
		},
		{
			name:        "mismatched lengths return error",
			origins:     []string{"https://site1.com", "https://site2.com"},
			emails:      []string{"test@example.com"},
			wantErr:     true,
			errContains: "CLIENT_ORIGINS and CLIENT_EMAILS must have the same number of entries",
		},
		{
			name:    "valid config returns nil",
			origins: []string{"https://site1.com", "https://site2.com"},
			emails:  []string{"test1@example.com", "test2@example.com"},
			wantErr: false,
		},
		{
			name: "duplicate origins returns nil (logs warning)",
			// Note: Implementation should log a warning for duplicates, but still return nil
			origins: []string{"https://site1.com", "https://site1.com"},
			emails:  []string{"test1@example.com", "test2@example.com"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClientConfig(tt.origins, tt.emails)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateClientConfig() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateClientConfig() error = %v, should contain %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateClientConfig() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestNormalizeOrigin(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "whitespace trimming",
			input: "  https://example.com  ",
			want:  "https://example.com",
		},
		{
			name:  "case normalization",
			input: "HTTPS://EXAMPLE.COM",
			want:  "https://example.com",
		},
		{
			name:  "empty string handling",
			input: "",
			want:  "",
		},
		{
			name:  "whitespace and case normalization combined",
			input: "  HTTPS://EXAMPLE.COM/PATH  ",
			want:  "https://example.com/path",
		},
		{
			name:  "already normalized",
			input: "https://example.com",
			want:  "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeOrigin(tt.input)
			if got != tt.want {
				t.Errorf("normalizeOrigin() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetDestinationEmail(t *testing.T) {
	tests := []struct {
		name          string
		origin        string
		clientOrigins []string
		clientEmails  []string
		wantEmail     string
		wantMatched   bool
	}{
		{
			name:          "exact match returns correct email",
			origin:        "https://site1.com",
			clientOrigins: []string{"https://site1.com", "https://site2.com"},
			clientEmails:  []string{"site1@example.com", "site2@example.com"},
			wantEmail:     "site1@example.com",
			wantMatched:   true,
		},
		{
			name:          "case-insensitive matching",
			origin:        "HTTPS://SITE1.COM",
			clientOrigins: []string{"https://site1.com", "https://site2.com"},
			clientEmails:  []string{"site1@example.com", "site2@example.com"},
			wantEmail:     "site1@example.com",
			wantMatched:   true,
		},
		{
			name:          "no match returns empty string and matched=false",
			origin:        "https://unknown.com",
			clientOrigins: []string{"https://site1.com", "https://site2.com"},
			clientEmails:  []string{"site1@example.com", "site2@example.com"},
			wantEmail:     "",
			wantMatched:   false,
		},
		{
			name:          "empty origin returns empty string and matched=false",
			origin:        "",
			clientOrigins: []string{"https://site1.com", "https://site2.com"},
			clientEmails:  []string{"site1@example.com", "site2@example.com"},
			wantEmail:     "",
			wantMatched:   false,
		},
		{
			name:          "first match wins with duplicates",
			origin:        "https://site1.com",
			clientOrigins: []string{"https://site1.com", "https://site1.com", "https://site2.com"},
			clientEmails:  []string{"first@example.com", "second@example.com", "site2@example.com"},
			wantEmail:     "first@example.com",
			wantMatched:   true,
		},
		{
			name:          "whitespace in origin is handled",
			origin:        "  https://site1.com  ",
			clientOrigins: []string{"https://site1.com", "https://site2.com"},
			clientEmails:  []string{"site1@example.com", "site2@example.com"},
			wantEmail:     "site1@example.com",
			wantMatched:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEmail, gotMatched := getDestinationEmail(tt.origin, tt.clientOrigins, tt.clientEmails)
			if gotEmail != tt.wantEmail {
				t.Errorf("getDestinationEmail() gotEmail = %q, want %q", gotEmail, tt.wantEmail)
			}
			if gotMatched != tt.wantMatched {
				t.Errorf("getDestinationEmail() gotMatched = %v, want %v", gotMatched, tt.wantMatched)
			}
		})
	}
}
