package db

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// DynamoDB Local does not enforce IAM, so a DynamoDB action the code uses but
// the Lambda role lacks only fails in prod (#214: ConditionCheckItem, 22 call
// sites, every such transaction 500ed). This statically maps each action the
// non-test code in this package needs onto the actions granted in
// terraform/lambda.tf. Transactions are authorized per item action, so each
// types.Put/Update/Delete/ConditionCheck/Get literal needs its own action as well
// as TransactWriteItems.
var (
	ddbCallRe = regexp.MustCompile(`\.ddb\.([A-Z][A-Za-z]+)\(`)
	txItemRe  = regexp.MustCompile(`types\.(Put|Update|Delete|ConditionCheck|Get)\{`)
	grantRe   = regexp.MustCompile(`"dynamodb:([A-Za-z]+)"`)
)

var txItemAction = map[string]string{
	"Put":            "PutItem",
	"Get":            "GetItem",
	"Update":         "UpdateItem",
	"Delete":         "DeleteItem",
	"ConditionCheck": "ConditionCheckItem",
}

// ddbCallsIgnored are client methods that make no DynamoDB request.
var ddbCallsIgnored = map[string]bool{"Options": true}

// neededActions returns each DynamoDB action the package's non-test code
// uses, with the first place it appears.
func neededActions(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	need := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			where := fmt.Sprintf("%s:%d", f, i+1)
			for _, m := range ddbCallRe.FindAllStringSubmatch(line, -1) {
				if !ddbCallsIgnored[m[1]] && need[m[1]] == "" {
					need[m[1]] = where
				}
			}
			for _, m := range txItemRe.FindAllStringSubmatch(line, -1) {
				if a := txItemAction[m[1]]; need[a] == "" {
					need[a] = where
				}
			}
		}
	}
	return need
}

// grantedActions returns the dynamodb:* actions in the Lambda execution
// role's policy document in terraform/lambda.tf.
func grantedActions(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "terraform", "lambda.tf"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, `data "aws_iam_policy_document" "lambda_policy"`)
	if start < 0 {
		t.Fatal("lambda_policy document not found in terraform/lambda.tf")
	}
	end := strings.Index(s[start:], `resource "aws_iam_role_policy" "lambda"`)
	if end < 0 {
		t.Fatal("end of lambda_policy document not found in terraform/lambda.tf")
	}
	granted := map[string]bool{}
	for _, m := range grantRe.FindAllStringSubmatch(s[start:start+end], -1) {
		granted[m[1]] = true
	}
	return granted
}

func TestLambdaPolicyGrantsEveryDynamoDBActionTheCodeUses(t *testing.T) {
	need := neededActions(t)
	// Guard against the scan silently matching nothing (a renamed client field
	// or literal would otherwise turn this into a pass).
	for _, a := range []string{"GetItem", "PutItem", "Query", "TransactWriteItems", "ConditionCheckItem"} {
		if need[a] == "" {
			t.Fatalf("scan found no use of %s; has the db client or transaction literal been renamed?", a)
		}
	}
	granted := grantedActions(t)

	var missing []string
	for a, where := range need {
		if !granted[a] {
			missing = append(missing, fmt.Sprintf("dynamodb:%s (first used at %s)", a, where))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("terraform/lambda.tf does not grant:\n  %s", strings.Join(missing, "\n  "))
	}
}
