package dkimheader

import (
	"strings"
	"testing"
)

func TestParseSignatureParams(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name:  "Valid DKIM-Signature with all required tags including v=1",
			input: "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1",
			want: map[string]string{
				"a":  "rsa-sha256",
				"b":  "signature",
				"bh": "bodyhash",
				"d":  "example.org",
				"h":  "from:to",
				"s":  "selector",
				"v":  "1",
			},
			wantErr: false,
		},
		{
			name:  "Valid DKIM-Signature with v=1 and extra tags",
			input: "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1; t=1234567890",
			want: map[string]string{
				"a":  "rsa-sha256",
				"b":  "signature",
				"bh": "bodyhash",
				"d":  "example.org",
				"h":  "from:to",
				"s":  "selector",
				"v":  "1",
				"t":  "1234567890",
			},
			wantErr: false,
		},
		{
			name:    "Missing v tag should result in error",
			input:   "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector",
			wantErr: true,
			errMsg:  "required tag 'v' is missing",
		},
		{
			name:    "Invalid v tag value should result in error",
			input:   "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=2",
			wantErr: true,
			errMsg:  "invalid version tag value",
		},
		{
			name:    "Empty v tag value should result in error",
			input:   "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=",
			wantErr: true,
			errMsg:  "invalid version tag value",
		},
		{
			name:  "Valid DKIM-Signature with whitespace",
			input: " a=rsa-sha256 ; b=signature ; bh=bodyhash ; d=example.org ; h=from:to ; s=selector ; v=1 ",
			want: map[string]string{
				"a":  "rsa-sha256",
				"b":  "signature",
				"bh": "bodyhash",
				"d":  "example.org",
				"h":  "from:to",
				"s":  "selector",
				"v":  "1",
			},
			wantErr: false,
		},
		{
			name:    "Duplicate tags should result in error",
			input:   "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1; v=1",
			wantErr: true,
			errMsg:  "duplicate tag",
		},
		{
			name:    "Malformed header params should result in error",
			input:   "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v",
			wantErr: true,
			errMsg:  "malformed header params",
		},
		{
			name:    "Missing other required tags should result in error",
			input:   "a=rsa-sha256; v=1",
			wantErr: true,
			errMsg:  "required tag",
		},
		{
			name:    "Empty tag name should result in error",
			input:   "=value",
			wantErr: true,
			errMsg:  "malformed header params",
		},
		{
			name:  "Empty tag value should be accepted",
			input: "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1; empty=",
			want: map[string]string{
				"a":     "rsa-sha256",
				"b":     "signature",
				"bh":    "bodyhash",
				"d":     "example.org",
				"h":     "from:to",
				"s":     "selector",
				"v":     "1",
				"empty": "",
			},
			wantErr: false,
		},
		{
			name:    "Very long tag name should be rejected",
			input:   "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1; " + strings.Repeat("x", 1000) + "=value",
			wantErr: true,
			errMsg:  "malformed header params",
		},
		{
			name:    "Very long tag value should be rejected",
			input:   "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1; tag=" + strings.Repeat("x", 10000),
			wantErr: true,
			errMsg:  "malformed header params",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSignatureParams(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatureParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseSignatureParams() error message = %v, wantErrMsg %v", err.Error(), tt.errMsg)
				}
			}

			if !tt.wantErr && err == nil {
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("ParseSignatureParams()[%s] = %v, want %v", k, got[k], v)
					}
				}

				// Check that we don't have extra keys beyond what we expect
				for k := range got {
					if _, exists := tt.want[k]; !exists {
						t.Errorf("ParseSignatureParams() got unexpected key %s", k)
					}
				}
			}
		})
	}
}

// Test cases for unknown tags (must be ignored according to RFC 6376 §3.2)
func TestParseSignatureParamsUnknownTags(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "Unknown tags should be ignored",
			input: "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1; unknown=value; another=tag",
			want: map[string]string{
				"a":  "rsa-sha256",
				"b":  "signature",
				"bh": "bodyhash",
				"d":  "example.org",
				"h":  "from:to",
				"s":  "selector",
				"v":  "1",
			},
		},
		{
			name:    "Only unknown tags",
			input:   "unknown=value; another=tag; third=param",
			want:    map[string]string{},
			wantErr: true,
		},
		{
			name:  "Only unknown tags with required tags",
			input: "a=rsa-sha256; b=signature; bh=bodyhash; d=example.org; h=from:to; s=selector; v=1; unknown=value; another=tag",
			want: map[string]string{
				"a":  "rsa-sha256",
				"b":  "signature",
				"bh": "bodyhash",
				"d":  "example.org",
				"h":  "from:to",
				"s":  "selector",
				"v":  "1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSignatureParams(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatureParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				// For error cases, we don't need to check the result values
				return
			}

			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("ParseSignatureParams()[%s] = %v, want %v", k, got[k], v)
				}
			}

			// Check that we don't have extra keys beyond what we expect
			for k := range got {
				if _, exists := tt.want[k]; !exists {
					t.Errorf("ParseSignatureParams() got unexpected key %s", k)
				}
			}
		})
	}
}
