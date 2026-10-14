// Command purge deletes automated-test accounts and the groups and rows they
// own (internal/db.PurgeTestAccounts). It runs as a scheduled Lambda, or once
// from a shell when AWS_LAMBDA_FUNCTION_NAME is unset, which is how it is run
// against DynamoDB Local.
//
// It fails safe: PURGE_DRY_RUN defaults to true and only the exact string
// "false" turns deletion on. An invocation payload may force a dry run
// ({"dryRun": true}) but can never turn deletion on, so a manual test
// invocation cannot be more destructive than the schedule's own setting.
//
// Environment: TABLE_NAME (required), PURGE_DRY_RUN, PURGE_MIN_AGE_HOURS
// (default 2), PURGE_MAX_ACCOUNTS (default 100), DYNAMODB_ENDPOINT (local only).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/pwntato/undergroundbb/internal/db"
)

const defaultMinAgeHours = 2

// event is the optional invocation payload.
type event struct {
	DryRun *bool `json:"dryRun"`
}

// options builds the run's options from the environment and the payload.
func options(getenv func(string) string, ev event) (db.PurgeOptions, error) {
	opts := db.PurgeOptions{
		DryRun:      getenv("PURGE_DRY_RUN") != "false",
		MinAge:      defaultMinAgeHours * time.Hour,
		MaxAccounts: db.DefaultPurgeMaxAccounts,
	}
	if ev.DryRun != nil && *ev.DryRun {
		opts.DryRun = true
	}
	if v := getenv("PURGE_MIN_AGE_HOURS"); v != "" {
		h, err := strconv.ParseFloat(v, 64)
		if err != nil || h < 0 {
			return opts, fmt.Errorf("PURGE_MIN_AGE_HOURS=%q: want a number of hours >= 0", v)
		}
		opts.MinAge = time.Duration(h * float64(time.Hour))
	}
	if v := getenv("PURGE_MAX_ACCOUNTS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return opts, fmt.Errorf("PURGE_MAX_ACCOUNTS=%q: want a positive integer", v)
		}
		opts.MaxAccounts = n
	}
	return opts, nil
}

func run(ctx context.Context, ev event) (db.PurgeReport, error) {
	table := os.Getenv("TABLE_NAME")
	if table == "" {
		return db.PurgeReport{}, fmt.Errorf("TABLE_NAME is not set")
	}
	opts, err := options(os.Getenv, ev)
	if err != nil {
		return db.PurgeReport{}, err
	}
	client, err := db.New(ctx, table, os.Getenv("DYNAMODB_ENDPOINT"))
	if err != nil {
		return db.PurgeReport{}, err
	}
	report, err := client.PurgeTestAccounts(ctx, opts)
	out, _ := json.Marshal(report)
	log.Printf("purge report: %s", out)
	return report, err
}

func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(run)
		return
	}
	if _, err := run(context.Background(), event{}); err != nil {
		log.Fatalf("purge: %v", err)
	}
}
