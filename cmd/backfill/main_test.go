package main

import "testing"

func TestDryRun(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name string
		env  string
		ev   event
		want bool
	}{
		{"unset defaults to dry run", "", event{}, true},
		{"garbage defaults to dry run", "no", event{}, true},
		{"only exact false writes", "false", event{}, false},
		{"payload forces a dry run", "false", event{DryRun: &yes}, true},
		{"payload cannot turn writing on", "true", event{DryRun: &no}, true},
		{"payload false does not override the env's dry run", "", event{DryRun: &no}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dryRun(func(string) string { return tt.env }, tt.ev)
			if got != tt.want {
				t.Errorf("dryRun = %v, want %v", got, tt.want)
			}
		})
	}
}
