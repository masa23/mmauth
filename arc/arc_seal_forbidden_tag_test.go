package arc

import (
	"testing"
)

func TestParseARCSealForbiddenTags(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "Valid ARC-Seal without forbidden tags",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr: false,
		},
		{
			name: "ARC-Seal with forbidden 'h' tag",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; h=From:To;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr: true,
		},
		{
			name: "ARC-Seal with forbidden 'bh' tag",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; bh=bodyhash;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr: true,
		},
		{
			name: "ARC-Seal with both forbidden tags",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; h=From:To; bh=bodyhash;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseARCSeal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseARCSeal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				// Check that the error message contains information about forbidden tags
				expectedErrMsgs := []string{"forbidden tag", "h", "bh"}
				errMsg := err.Error()
				found := false
				for _, expected := range expectedErrMsgs {
					if contains(errMsg, expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ParseARCSeal() error message should mention forbidden tags, got: %v", errMsg)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) < len(s) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || contains(s[1:len(s)-1], substr)))
}
