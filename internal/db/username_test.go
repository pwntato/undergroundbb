package db

import (
	"context"
	"testing"
)

func TestUsernameAvailableTrueWhenUnclaimed(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "avail-unclaimed-" + randomSuffix(t)
	available, err := c.UsernameAvailable(ctx, username)
	if err != nil {
		t.Fatalf("UsernameAvailable: %v", err)
	}
	if !available {
		t.Error("UsernameAvailable = false, want true for a name nobody has registered")
	}
}

func TestUsernameAvailableFalseAfterRegister(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "avail-claimed-" + randomSuffix(t)
	in := testRegisterInput("test-avail-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	available, err := c.UsernameAvailable(ctx, username)
	if err != nil {
		t.Fatalf("UsernameAvailable: %v", err)
	}
	if available {
		t.Error("UsernameAvailable = true, want false immediately after Register claimed it")
	}
}
