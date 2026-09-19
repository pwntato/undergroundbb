package idgen

import (
	"regexp"
	"testing"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUUIDFormat(t *testing.T) {
	id, err := UUID()
	if err != nil {
		t.Fatalf("UUID: %v", err)
	}
	if !uuidPattern.MatchString(id) {
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
