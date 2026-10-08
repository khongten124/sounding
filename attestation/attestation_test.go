package attestation

import (
	"testing"
	"time"
)

func TestBuildCorridorID(t *testing.T) {
	tests := []struct {
		name         string
		sendAsset    string
		receiveAsset string
		want         string
	}{
		{
			name:         "standard uppercase assets",
			sendAsset:    "USDC",
			receiveAsset: "NGNC",
			want:         "USDC→NGNC", // USDC→NGNC
		},
		{
			name:         "preserves lowercase without uppercasing",
			sendAsset:    "usdc",
			receiveAsset: "ngnc",
			want:         "usdc→ngnc", // usdc→ngnc
		},
		{
			name:         "preserves whitespace without trimming",
			sendAsset:    " USDC ",
			receiveAsset: " NGNC ",
			want:         " USDC → NGNC ",
		},
		{
			name:         "empty send asset",
			sendAsset:    "",
			receiveAsset: "XLM",
			want:         "→XLM",
		},
		{
			name:         "empty receive asset",
			sendAsset:    "XLM",
			receiveAsset: "",
			want:         "XLM→",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildCorridorID(tt.sendAsset, tt.receiveAsset)
			if got != tt.want {
				t.Errorf("BuildCorridorID(%q, %q) = %q, want %q", tt.sendAsset, tt.receiveAsset, got, tt.want)
			}

			// Verify exact byte sequence including the U+2192 rightwards arrow (E2 86 92)
			expectedArrowBytes := []byte("→")
			if len(expectedArrowBytes) != 3 || expectedArrowBytes[0] != 0xe2 || expectedArrowBytes[1] != 0x86 || expectedArrowBytes[2] != 0x92 {
				t.Fatalf("unexpected byte representation for arrow separator")
			}
		})
	}
}

func TestAttestationFromMeasurement(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	nowStr := now.Format(time.RFC3339)

	t.Run("valid measurement with recommended rung", func(t *testing.T) {
		corridorID := "USDC→NGNC"
		measurement := map[string]interface{}{
			"integrity":     "DIRECT",
			"reference_mid": "1550.25",
			"measured_at":   nowStr,
			"recommended": map[string]interface{}{
				"verdict":  "GOOD",
				"loss_pct": "1.25",
			},
		}

		att, err := AttestationFromMeasurement(corridorID, measurement)
		if err != nil {
			t.Fatalf("AttestationFromMeasurement() unexpected error = %v", err)
		}
		if att == nil {
			t.Fatal("AttestationFromMeasurement() returned nil attestation")
		}

		if att.CorridorID != corridorID {
			t.Errorf("CorridorID = %q, want %q", att.CorridorID, corridorID)
		}
		if att.Integrity != IntegrityDirect {
			t.Errorf("Integrity = %q, want %q", att.Integrity, IntegrityDirect)
		}
		if att.BestVerdict != VerdictGood {
			t.Errorf("BestVerdict = %q, want %q", att.BestVerdict, VerdictGood)
		}
		if att.LossPct != "1.25" {
			t.Errorf("LossPct = %q, want %q", att.LossPct, "1.25")
		}
		if att.ReferenceMid != "1550.25" {
			t.Errorf("ReferenceMid = %q, want %q", att.ReferenceMid, "1550.25")
		}
		if !att.MeasuredAt.Equal(now) {
			t.Errorf("MeasuredAt = %v, want %v", att.MeasuredAt, now)
		}
	})

	t.Run("measurement without recommended rung defaults to UNUSABLE and 100.00 loss", func(t *testing.T) {
		corridorID := "USDC→NGNC"
		measurement := map[string]interface{}{
			"integrity":     "NO-MARKET",
			"reference_mid": "",
			"measured_at":   nowStr,
		}

		att, err := AttestationFromMeasurement(corridorID, measurement)
		if err != nil {
			t.Fatalf("AttestationFromMeasurement() unexpected error = %v", err)
		}
		if att == nil {
			t.Fatal("AttestationFromMeasurement() returned nil attestation")
		}

		if att.BestVerdict != VerdictUnusable {
			t.Errorf("BestVerdict = %q, want %q", att.BestVerdict, VerdictUnusable)
		}
		if att.LossPct != "100.00" {
			t.Errorf("LossPct = %q, want %q", att.LossPct, "100.00")
		}
		if att.Integrity != IntegrityNoMarket {
			t.Errorf("Integrity = %q, want %q", att.Integrity, IntegrityNoMarket)
		}
	})

	t.Run("missing integrity field returns error", func(t *testing.T) {
		corridorID := "USDC→NGNC"
		measurement := map[string]interface{}{
			"reference_mid": "1550.25",
			"measured_at":   nowStr,
			"recommended": map[string]interface{}{
				"verdict":  "GOOD",
				"loss_pct": "1.25",
			},
		}

		att, err := AttestationFromMeasurement(corridorID, measurement)
		if err == nil {
			t.Errorf("AttestationFromMeasurement() expected error for missing integrity, got nil")
		}
		if att != nil {
			t.Errorf("AttestationFromMeasurement() expected nil attestation on error, got %+v", att)
		}
	})

	t.Run("non-string integrity field returns error", func(t *testing.T) {
		corridorID := "USDC→NGNC"
		measurement := map[string]interface{}{
			"integrity": 12345, // invalid type
		}

		att, err := AttestationFromMeasurement(corridorID, measurement)
		if err == nil {
			t.Errorf("AttestationFromMeasurement() expected error for non-string integrity, got nil")
		}
		if att != nil {
			t.Errorf("AttestationFromMeasurement() expected nil attestation on error, got %+v", att)
		}
	})

	t.Run("invalid measured_at timestamp falls back to non-zero time", func(t *testing.T) {
		corridorID := "USDC→NGNC"
		measurement := map[string]interface{}{
			"integrity":   "DERIVATIVE",
			"measured_at": "invalid-timestamp",
		}

		before := time.Now().Add(-1 * time.Second)
		att, err := AttestationFromMeasurement(corridorID, measurement)
		after := time.Now().Add(1 * time.Second)

		if err != nil {
			t.Fatalf("AttestationFromMeasurement() unexpected error = %v", err)
		}
		if att == nil {
			t.Fatal("AttestationFromMeasurement() returned nil attestation")
		}

		if att.MeasuredAt.Before(before) || att.MeasuredAt.After(after) {
			t.Errorf("MeasuredAt timestamp %v is not around current time", att.MeasuredAt)
		}
	})
}
