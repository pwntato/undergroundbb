package main

import (
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestOptionsFailSafeToDryRun(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		env  map[string]string
		ev   event
		want bool
	}{
		{"unset", nil, event{}, true},
		{"empty", map[string]string{"PURGE_DRY_RUN": ""}, event{}, true},
		{"garbage", map[string]string{"PURGE_DRY_RUN": "0"}, event{}, true},
		{"true", map[string]string{"PURGE_DRY_RUN": "true"}, event{}, true},
		{"capitalised false is not false", map[string]string{"PURGE_DRY_RUN": "False"}, event{}, true},
		{"false deletes", map[string]string{"PURGE_DRY_RUN": "false"}, event{}, false},
		{"payload can force a dry run", map[string]string{"PURGE_DRY_RUN": "false"}, event{DryRun: &yes}, true},
		{"payload cannot turn deletion on", map[string]string{"PURGE_DRY_RUN": "true"}, event{DryRun: &no}, true},
		{"payload false changes nothing when deleting", map[string]string{"PURGE_DRY_RUN": "false"}, event{DryRun: &no}, false},
	}
	for _, tc := range cases {
		opts, err := options(env(tc.env), tc.ev)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if opts.DryRun != tc.want {
			t.Errorf("%s: DryRun = %v, want %v", tc.name, opts.DryRun, tc.want)
		}
	}
}

func TestOptionsParseLimitsAndRejectBadValues(t *testing.T) {
	opts, err := options(env(map[string]string{"PURGE_MIN_AGE_HOURS": "0.5", "PURGE_MAX_ACCOUNTS": "7"}), event{})
	if err != nil || opts.MinAge != 30*time.Minute || opts.MaxAccounts != 7 {
		t.Errorf("opts = %+v err = %v, want 30m and 7", opts, err)
	}
	def, _ := options(env(nil), event{})
	if def.MinAge != 2*time.Hour || def.MaxAccounts != 100 {
		t.Errorf("defaults = %+v, want 2h and 100", def)
	}
	for _, bad := range []map[string]string{
		{"PURGE_MIN_AGE_HOURS": "-1"}, {"PURGE_MIN_AGE_HOURS": "soon"},
		{"PURGE_MAX_ACCOUNTS": "0"}, {"PURGE_MAX_ACCOUNTS": "many"},
	} {
		if _, err := options(env(bad), event{}); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
}
