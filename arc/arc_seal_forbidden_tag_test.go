package arc

import (
	"testing"
)

func TestParseARCSealForbiddenTags(t *testing.T) {
	tests := []struct {
		name                string
		input               string
		wantErr             bool
		wantChainValidation ChainValidationResult
	}{
		{
			name: "Valid ARC-Seal without forbidden tags",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr:             false,
			wantChainValidation: ChainValidationResultNone,
		},
		{
			name: "ARC-Seal with forbidden 'h' tag",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; h=From:To;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr:             false,                     // エラーを返さない
			wantChainValidation: ChainValidationResultFail, // cv=failが設定されることを確認
		},
		{
			name: "ARC-Seal with forbidden 'bh' tag",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; bh=bodyhash;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr:             false,                     // エラーを返さない
			wantChainValidation: ChainValidationResultFail, // cv=failが設定されることを確認
		},
		{
			name: "ARC-Seal with both forbidden tags",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; h=From:To; bh=bodyhash;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr:             false,                     // エラーを返さない
			wantChainValidation: ChainValidationResultFail, // cv=failが設定されることを確認
		},
		{
			name: "ARC-Seal with uppercase 'H' tag",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; H=From:To;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr:             false,                     // エラーを返さない
			wantChainValidation: ChainValidationResultFail, // cv=failが設定されることを確認
		},
		{
			name: "ARC-Seal with uppercase 'BH' tag",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; BH=bodyhash;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr:             false,                     // エラーを返さない
			wantChainValidation: ChainValidationResultFail, // cv=failが設定されることを確認
		},
		{
			name: "ARC-Seal with mixed case 'h' tag",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; H=From:To;\r\n" +
				"        d=example.org; s=selector;\r\n" +
				"        b=signature",
			wantErr:             false,                     // エラーを返さない
			wantChainValidation: ChainValidationResultFail, // cv=failが設定されることを確認
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseARCSeal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseARCSeal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantChainValidation != "" && result.ChainValidation != tt.wantChainValidation {
				t.Errorf("ParseARCSeal() chainValidation = %v, wantChainValidation %v", result.ChainValidation, tt.wantChainValidation)
			}
		})
	}
}
