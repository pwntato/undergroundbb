package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestTripSetsTargetToZeroWhateverTheMessage(t *testing.T) {
	for name, ev := range map[string]events.SNSEvent{
		"no records":     {},
		"alarm":          {Records: []events.SNSEventRecord{{SNS: events.SNSEntity{Subject: "ALARM: x"}}}},
		"garbage record": {Records: []events.SNSEventRecord{{SNS: events.SNSEntity{Message: "{not json"}}}},
	} {
		var gotFn string
		gotLimit := int32(-1)
		set := func(_ context.Context, fn string, limit int32) error { gotFn, gotLimit = fn, limit; return nil }
		if err := trip(context.Background(), "web", set, ev); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if gotFn != "web" || gotLimit != 0 {
			t.Errorf("%s: set(%q, %d), want set(\"web\", 0)", name, gotFn, gotLimit)
		}
	}
}

func TestTripReportsFailuresSoLambdaRetries(t *testing.T) {
	boom := errors.New("access denied")
	err := trip(context.Background(), "web", func(context.Context, string, int32) error { return boom }, events.SNSEvent{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the AWS error", err)
	}
}

func TestTripRefusesWithoutATarget(t *testing.T) {
	called := false
	err := trip(context.Background(), "", func(context.Context, string, int32) error { called = true; return nil }, events.SNSEvent{})
	if err == nil || called {
		t.Fatalf("err = %v, called = %v; want an error and no call", err, called)
	}
}
