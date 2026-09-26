package idgen

import (
	"regexp"
	"testing"
	"time"
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

// daySuffixPattern matches DaySuffix's output shape exactly: a UTC calendar
// day followed by 16 lowercase hex characters (8 random bytes).
var daySuffixPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}#[0-9a-f]{16}$`)

func TestDaySuffixFormat(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	s, err := DaySuffix(now)
	if err != nil {
		t.Fatalf("DaySuffix: %v", err)
	}
	if !daySuffixPattern.MatchString(s) {
		t.Errorf("DaySuffix(%v) = %q, does not match the expected <YYYY-MM-DD>#<hex> shape", now, s)
	}
	const wantDay = "2026-09-25"
	if s[:len(wantDay)] != wantDay {
		t.Errorf("DaySuffix(%v) = %q, want day component %q", now, s, wantDay)
	}
}

// TestDaySuffixUsesUTC covers the reason DaySuffix calls now.UTC() itself
// rather than trusting the caller to pass a UTC time: a local time one
// timezone offset away from a day boundary must still resolve to the same
// day every server instance would compute, not the day it happens to be in
// whatever offset the caller passed.
func TestDaySuffixUsesUTC(t *testing.T) {
	// 2026-09-25 23:30 in UTC+2 is 2026-09-25 21:30 UTC -- same day. Pick an
	// instant where the local and UTC calendar days actually differ instead.
	loc := time.FixedZone("UTC+2", 2*60*60)
	local := time.Date(2026, 9, 26, 0, 30, 0, 0, loc) // 2026-09-25 22:30 UTC
	s, err := DaySuffix(local)
	if err != nil {
		t.Fatalf("DaySuffix: %v", err)
	}
	const wantDay = "2026-09-25"
	if s[:len(wantDay)] != wantDay {
		t.Errorf("DaySuffix(%v) = %q, want UTC day component %q, not the local day", local, s, wantDay)
	}
}

// TestDaySuffixUnique is the same sanity check TestUUIDUnique performs for
// UUID: not a proof, but it catches a broken CSPRNG call (a fixed seed, a
// reused buffer) that would otherwise pass a single-call format check.
func TestDaySuffixUnique(t *testing.T) {
	now := time.Now()
	seen := make(map[string]bool, 1000)
	for range 1000 {
		s, err := DaySuffix(now)
		if err != nil {
			t.Fatalf("DaySuffix: %v", err)
		}
		if seen[s] {
			t.Fatalf("duplicate DaySuffix generated: %q", s)
		}
		seen[s] = true
	}
}

// TestValidGrantSortKeyAccepts covers the exact shape DaySuffix combined
// with a subject uuid produces -- a well-formed GRANT# sort key for the
// subject it addresses must parse and return its day.
func TestValidGrantSortKeyAccepts(t *testing.T) {
	const subjectUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	key := "GRANT#" + subjectUUID + "#2026-09-25#a1b2c3d4e5f6a1b2"

	day, ok := ValidGrantSortKey(key, subjectUUID)
	if !ok {
		t.Fatalf("ValidGrantSortKey(%q, %q) = false, want true", key, subjectUUID)
	}
	want := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	if !day.Equal(want) {
		t.Errorf("ValidGrantSortKey(%q, %q) day = %v, want %v", key, subjectUUID, day, want)
	}
}

// TestValidGrantSortKeyRejects covers ValidGrantSortKey's shape and
// subject-binding checks -- a well-formed key for the WRONG subject must be
// rejected just as loudly as a malformed one, since a grant sort key is
// meaningless (and unqueryable) outside the one subject's chain it
// addresses.
func TestValidGrantSortKeyRejects(t *testing.T) {
	const subjectUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	const otherUUID = "a1a1a1a1-58cc-4372-a567-0e02b2c3d479"

	cases := map[string]string{
		"wrong subject uuid":  "GRANT#" + otherUUID + "#2026-09-25#a1b2c3d4e5f6a1b2",
		"missing GRANT# tag":  subjectUUID + "#2026-09-25#a1b2c3d4e5f6a1b2",
		"bad day shape":       "GRANT#" + subjectUUID + "#2026-9-25#a1b2c3d4e5f6a1b2",
		"short random suffix": "GRANT#" + subjectUUID + "#2026-09-25#a1b2",
		"uppercase hex":       "GRANT#" + subjectUUID + "#2026-09-25#A1B2C3D4E5F6A1B2",
		"empty string":        "",
	}
	for name, key := range cases {
		if _, ok := ValidGrantSortKey(key, subjectUUID); ok {
			t.Errorf("%s: ValidGrantSortKey(%q, %q) = true, want false", name, key, subjectUUID)
		}
	}
}
