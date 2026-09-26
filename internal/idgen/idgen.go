// Package idgen generates the random identifiers this project's schema
// calls for.
//
// docs/DESIGN.md is deliberate that ids are random, not time-ordered (e.g.
// "a ULID sort key leaking millisecond timestamps" was a design defect this
// project specifically corrected) -- so every id here comes from a CSPRNG,
// never a counter or a clock.
package idgen

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"time"
)

// uuidPattern matches exactly what UUID produces: a well-formed, lowercase
// RFC 4122 version 4 UUID (idgen_test.go's own TestUUIDFormat asserts UUID's
// output against the same shape). Exported through ValidUUID rather than
// this pattern directly, since callers should never need to know the schema
// accepts UUIDs specifically, only whether a candidate id is one.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ValidUUID reports whether s is a well-formed, lowercase RFC 4122 version 4
// UUID -- the shape register.go requires of a client-supplied UserID (see
// registerRequest's own doc comment on why the client, not the server,
// generates this one id: the credential-wrap AAD is bound to it before the
// server is ever called). Uppercase hex and other UUID versions are
// rejected rather than normalized, since accepting a wider shape here than
// UUID itself ever produces would let a client-chosen id look different
// from every server-generated one in a table dump for no benefit.
func ValidUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

// UUID generates a random RFC 4122 version 4 UUID, e.g.
// "f47ac10b-58cc-4372-a567-0e02b2c3d479". It is used for every uuid this
// schema assigns server-side (group, invite, ...) -- 122 bits of CSPRNG
// output is far more than this project needs to rule out collision, and a
// UUID is a familiar, self-describing shape for anyone reading a table dump
// or a log line. The one exception is the user uuid, which the client
// generates itself (see ValidUUID's own doc comment for why) using this same
// shape, just not this function.
func UUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("idgen: generate uuid: %w", err)
	}
	// Version 4: set the version nibble to 0100.
	b[6] = (b[6] & 0x0f) | 0x40
	// Variant: set the two most significant bits of byte 8 to 10.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// randSuffixBytes is the width of the random component DaySuffix appends.
// 8 bytes (16 hex characters) is far more than needed to avoid a same-day
// collision within one partition -- the items this suffix addresses
// (GRANT#, and later POST#/INVITE#/NOTIF#) are written at most a handful of
// times a day even for a very active group -- but costs nothing extra on a
// sort key that already carries a uuid and a date.
const randSuffixBytes = 8

// DaySuffix generates the "<YYYY-MM-DD, UTC>#<rand>" component several sort
// keys in docs/DESIGN.md's data model use (GRANT#<uuid>#<YYYY-MM-DD>#<rand>,
// and later POST#, INVITE#, NOTIF#) -- a day-resolution timestamp, which is
// deliberately coarser than a full RFC 3339 value so the key discloses only
// the day something happened rather than the second (see DESIGN.md's TTL
// rounding discussion for why second-resolution values are avoided
// elsewhere in this schema too), followed by CSPRNG randomness so two items
// written the same day never collide and so the key does not become a
// second, finer-grained clock in disguise. now is UTC, not local time, so
// every server instance and every reader agrees on which day a given
// instant falls in regardless of where it runs.
func DaySuffix(now time.Time) (string, error) {
	var b [randSuffixBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("idgen: generate day suffix: %w", err)
	}
	return fmt.Sprintf("%s#%x", now.UTC().Format("2006-01-02"), b[:]), nil
}
