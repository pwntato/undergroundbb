package idgen

import (
	"testing"
)

func TestUUIDFormat(t *testing.T) {
	id, err := UUID()
	if err != nil {
		t.Fatalf("UUID: %v", err)
	}
	if !ValidUUID(id) {
		t.Errorf("UUID() = %q, does not match RFC 4122 v4 shape", id)
	}
}

// TestUUIDUnique isn't a proof of uniqueness -- 122 bits of CSPRNG output
// makes a collision astronomically unlikely, not impossible -- but it does
// catch the class of bug that would make this not actually be random (a
// fixed seed, a counter mistaken for rand.Read, a copy-paste that reused a
// buffer across calls).
func TestUUIDUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		id, err := UUID()
		if err != nil {
			t.Fatalf("UUID: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate UUID generated: %q", id)
		}
		seen[id] = true
	}
}

func TestValidUUIDAcceptsGenerated(t *testing.T) {
	id, err := UUID()
	if err != nil {
		t.Fatalf("UUID: %v", err)
	}
	if !ValidUUID(id) {
		t.Errorf("ValidUUID(%q) = false, want true for a freshly generated id", id)
	}
}

func TestValidUUIDRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"uppercase", "F47AC10B-58CC-4372-A567-0E02B2C3D479"},
		{"wrong version nibble", "f47ac10b-58cc-1372-a567-0e02b2c3d479"},
		{"wrong variant nibble", "f47ac10b-58cc-4372-1567-0e02b2c3d479"},
		{"missing hyphens", "f47ac10b58cc4372a5670e02b2c3d479"},
		{"too short", "f47ac10b-58cc-4372-a567-0e02b2c3d47"},
		{"too long", "f47ac10b-58cc-4372-a567-0e02b2c3d4799"},
		{"non-hex characters", "g47ac10b-58cc-4372-a567-0e02b2c3d479"},
		{"trailing whitespace", "f47ac10b-58cc-4372-a567-0e02b2c3d479 "},
		{"path traversal attempt", "../../etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ValidUUID(tc.id) {
				t.Errorf("ValidUUID(%q) = true, want false", tc.id)
			}
		})
	}
}
