package devfortress

import "testing"

func TestConfigIntegrityVerifier_UnmodifiedConfigVerifiesClean(t *testing.T) {
	v := NewConfigIntegrityVerifier(nil, nil)
	cfg := map[string]any{"mode": "external", "blockThreshold": float64(80)}
	v.Seal(cfg)
	result := v.Verify(cfg)
	if !result.Valid || len(result.Violations) != 0 || result.CheckCount != 1 {
		t.Fatalf("expected clean verify, got %+v", result)
	}
}

func TestConfigIntegrityVerifier_TamperedCriticalFieldIsCritical(t *testing.T) {
	v := NewConfigIntegrityVerifier(nil, nil)
	v.Seal(map[string]any{"mode": "external", "blockThreshold": float64(80)})
	result := v.Verify(map[string]any{"mode": "internal", "blockThreshold": float64(80)})
	if result.Valid || len(result.Violations) != 1 {
		t.Fatalf("expected one violation, got %+v", result)
	}
	if result.Violations[0].Field != "mode" || result.Violations[0].Severity != "CRITICAL" {
		t.Fatalf("expected mode/CRITICAL, got %+v", result.Violations[0])
	}
}

func TestConfigIntegrityVerifier_TamperedNonCriticalFieldIsHigh(t *testing.T) {
	v := NewConfigIntegrityVerifier(nil, nil)
	v.Seal(map[string]any{"debug": false})
	result := v.Verify(map[string]any{"debug": true})
	if result.Valid || result.Violations[0].Severity != "HIGH" {
		t.Fatalf("expected HIGH severity, got %+v", result)
	}
}

func TestConfigIntegrityVerifier_NestedDriftFoundWithDottedPath(t *testing.T) {
	v := NewConfigIntegrityVerifier(nil, nil)
	v.Seal(map[string]any{"limits": map[string]any{"rateLimitMax": float64(100)}})
	result := v.Verify(map[string]any{"limits": map[string]any{"rateLimitMax": float64(999)}})
	if result.Valid || result.Violations[0].Field != "limits.rateLimitMax" || result.Violations[0].Severity != "CRITICAL" {
		t.Fatalf("expected nested CRITICAL violation, got %+v", result)
	}
}

func TestConfigIntegrityVerifier_OnViolationCallbackFiresForEachViolation(t *testing.T) {
	var seen []string
	v := NewConfigIntegrityVerifier(nil, func(violation ConfigViolation) {
		seen = append(seen, violation.Field)
	})
	v.Seal(map[string]any{"a": float64(1), "b": float64(2)})
	v.Verify(map[string]any{"a": float64(9), "b": float64(9)})
	if len(seen) != 2 {
		t.Fatalf("expected 2 callback invocations, got %d: %v", len(seen), seen)
	}
}

func TestConfigIntegrityVerifier_ViolationsAccumulateAcrossCalls(t *testing.T) {
	v := NewConfigIntegrityVerifier(nil, nil)
	v.Seal(map[string]any{"a": float64(1)})
	v.Verify(map[string]any{"a": float64(2)})
	v.Verify(map[string]any{"a": float64(3)})
	status := v.GetStatus()
	if status.CheckCount != 2 || len(status.Violations) != 2 {
		t.Fatalf("expected 2 checks / 2 violations, got %+v", status)
	}
}

func TestConfigIntegrityVerifier_GetStatusWithoutVerifyingIsCleanAfterSeal(t *testing.T) {
	v := NewConfigIntegrityVerifier(nil, nil)
	v.Seal(map[string]any{"a": float64(1)})
	status := v.GetStatus()
	if !status.Valid || status.CheckCount != 0 {
		t.Fatalf("expected clean unchecked status, got %+v", status)
	}
}
