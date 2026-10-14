package db

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The purge Lambda runs under its own role (terraform/purge.tf), and DynamoDB
// Local does not enforce IAM, so a missing grant would only show up in prod
// and an extra one would never show up at all. This pins the role's
// dynamodb:* actions to exactly what cmd/purge uses, following the calls from
// PurgeTestAccounts into every helper it reaches, and nothing more. In
// particular no Scan, no PutItem and no Transact*: the purge deletes by key.

var clientCallRe = regexp.MustCompile(`\bc\.([a-z][A-Za-z]*)\(`)

// clientMethods maps each method name on *Client (non-test code) to its body.
func clientMethods(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	defRe := regexp.MustCompile(`(?m)^func \(c \*Client\) ([A-Za-z]+)\(`)
	methods := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		locs := defRe.FindAllStringSubmatchIndex(s, -1)
		for i, loc := range locs {
			end := len(s)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			methods[s[loc[2]:loc[3]]] = s[loc[0]:end]
		}
	}
	return methods
}

// purgeActionsUsed returns the DynamoDB actions the purge needs: those in
// PurgeTestAccounts and, transitively, in every *Client method it calls, in
// whichever file that method lives. A helper added later is picked up without
// editing this test.
func purgeActionsUsed(t *testing.T) []string {
	t.Helper()
	methods := clientMethods(t)
	if methods["PurgeTestAccounts"] == "" {
		t.Fatal("PurgeTestAccounts not found; the purge IAM test needs updating")
	}
	set := map[string]bool{}
	seen := map[string]bool{}
	var visit func(name string)
	visit = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		var body strings.Builder
		for _, line := range strings.Split(methods[name], "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "//") {
				body.WriteString(line + "\n")
			}
		}
		for _, m := range ddbCallRe.FindAllStringSubmatch(body.String(), -1) {
			if !ddbCallsIgnored[m[1]] {
				set[m[1]] = true
			}
		}
		for _, m := range txItemRe.FindAllStringSubmatch(body.String(), -1) {
			set[txItemAction[m[1]]] = true
		}
		for _, m := range clientCallRe.FindAllStringSubmatch(body.String(), -1) {
			if _, ok := methods[m[1]]; ok {
				visit(m[1])
			}
		}
	}
	visit("PurgeTestAccounts")
	return sorted(set)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// purgeGrantedActions returns the dynamodb:* actions in terraform/purge.tf's
// purge_policy document.
func purgeGrantedActions(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "terraform", "purge.tf"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, `data "aws_iam_policy_document" "purge_policy"`)
	if start < 0 {
		t.Fatal("purge_policy document not found in terraform/purge.tf")
	}
	end := strings.Index(s[start:], `resource "aws_iam_role_policy" "purge"`)
	if end < 0 {
		t.Fatal("end of purge_policy document not found in terraform/purge.tf")
	}
	set := map[string]bool{}
	for _, m := range grantRe.FindAllStringSubmatch(s[start:start+end], -1) {
		set[m[1]] = true
	}
	return sorted(set)
}

func TestPurgeRoleGrantsExactlyTheDynamoDBActionsThePurgeUses(t *testing.T) {
	used := purgeActionsUsed(t)
	// Guard against the scan silently matching nothing.
	for _, a := range []string{"Query", "GetItem", "DeleteItem", "UpdateItem", "BatchWriteItem"} {
		found := false
		for _, u := range used {
			found = found || u == a
		}
		if !found {
			t.Fatalf("scan found no use of %s; has the purge code or db client been renamed? used = %v", a, used)
		}
	}
	granted := purgeGrantedActions(t)
	if !reflect.DeepEqual(used, granted) {
		t.Errorf("terraform/purge.tf grants dynamodb:%v\ncmd/purge needs        dynamodb:%v", granted, used)
	}
}
