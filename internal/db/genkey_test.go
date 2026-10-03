package db

import "testing"

func TestGenKeySortKeyRoundTrips(t *testing.T) {
	for _, n := range []int64{0, 1, 42, 999999} {
		got, err := ParseGenKeySortKey(GenKeySortKey(n))
		if err != nil || got != n {
			t.Errorf("ParseGenKeySortKey(GenKeySortKey(%d)) = %d, %v", n, got, err)
		}
	}
}

func TestParseGenKeySortKeyRejectsOtherKeys(t *testing.T) {
	for _, sk := range []string{"", "GENKEY#", "GENKEY#abc", "ROTATION", "GRANT#000001", "genkey#000001"} {
		if _, err := ParseGenKeySortKey(sk); err == nil {
			t.Errorf("ParseGenKeySortKey(%q) succeeded, want an error", sk)
		}
	}
}
