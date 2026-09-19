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
)

// UUID generates a random RFC 4122 version 4 UUID, e.g.
// "f47ac10b-58cc-4372-a567-0e02b2c3d479". It is used for every uuid this
// schema assigns (user, group, invite, ...) -- 122 bits of CSPRNG output is
// far more than this project needs to rule out collision, and a UUID is a
// familiar, self-describing shape for anyone reading a table dump or a log
// line.
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
