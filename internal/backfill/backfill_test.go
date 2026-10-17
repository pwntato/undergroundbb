package backfill

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const fullRes = "2026-03-05T14:22:31Z"
const dayRes = "2026-03-05T00:00:00Z"

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func testClient(t *testing.T) (*dynamodb.Client, string) {
	t.Helper()
	endpoint := os.Getenv("DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DYNAMODB_ENDPOINT not set; run `docker compose up -d && ./scripts/local-setup.sh` to test against DynamoDB Local")
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	// A table of its own: Run scans the whole table, which on the shared
	// local table would read every other package's rows.
	table := "backfill-test-" + suffix(t)
	_, err = c.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName:   aws.String(table),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = c.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	})
	return c, table
}

func suffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type row struct{ pk, sk string }

// seed writes one row with CreatedAt = created (unset when empty).
func seed(t *testing.T, c *dynamodb.Client, table, pk, sk, typ, created string, extra map[string]types.AttributeValue) row {
	t.Helper()
	item := map[string]types.AttributeValue{"PK": s(pk), "SK": s(sk), "Type": s(typ)}
	if created != "" {
		item["CreatedAt"] = s(created)
	}
	for k, v := range extra {
		item[k] = v
	}
	if _, err := c.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(table), Item: item}); err != nil {
		t.Fatal(err)
	}
	return row{pk, sk}
}

// created returns the row's CreatedAt, or "" when the attribute is absent.
func created(t *testing.T, c *dynamodb.Client, table string, r row) string {
	t.Helper()
	out, err := c.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(table), ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{"PK": s(r.pk), "SK": s(r.sk)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return strAttr(out.Item, "CreatedAt")
}

type world struct {
	c     *dynamodb.Client
	table string
	// want maps each seeded row to the CreatedAt it must have after a real run.
	want map[row]string
	all  []row
}

func newWorld(t *testing.T) world {
	t.Helper()
	c, table := testClient(t)
	id := suffix(t)
	w := world{c: c, table: table, want: map[row]string{}}
	add := func(r row, after string) { w.want[r] = after; w.all = append(w.all, r) }

	add(seed(t, c, table, "USER#bf-"+id+"-real", "PROFILE", "User", fullRes, nil), "")
	add(seed(t, c, table, "USER#bf-"+id+"-test", "PROFILE", "User", fullRes,
		map[string]types.AttributeValue{"TestAccount": &types.AttributeValueMemberBOOL{Value: true}}), fullRes)
	add(seed(t, c, table, "USER#bf-"+id+"-real", "RECOVERY", "Recovery", fullRes, nil), "")
	add(seed(t, c, table, "USERNAME#bf-"+id, "CLAIM", "UsernameClaim", fullRes, nil), "")
	add(seed(t, c, table, "GROUP#bf-"+id, "META", "Group", fullRes, nil), "")
	add(seed(t, c, table, "GROUP#bf-"+id, "GRANT#root", "RoleGrant", fullRes, nil), "")
	add(seed(t, c, table, "GROUP#bf-"+id, "MEMBER#a", "Membership", fullRes, nil), dayRes)
	add(seed(t, c, table, "GROUP#bf-"+id, "MEMBER#b", "Membership", dayRes, nil), dayRes)
	// Out of scope for #147's backfill: left exactly as written.
	add(seed(t, c, table, "GROUP#bf-"+id, "ADMISSION#a", "Admission", fullRes, nil), fullRes)
	// No CreatedAt to begin with: the scan filter never returns it.
	add(seed(t, c, table, "GROUP#bf-"+id, "GRANT#other", "RoleGrant", "", nil), "")
	return w
}

func (w world) opts(dry bool) Options {
	return Options{DryRun: dry}
}

func (w world) assert(t *testing.T, want map[row]string) {
	t.Helper()
	for r, v := range want {
		if got := created(t, w.c, w.table, r); got != v {
			t.Errorf("%s/%s CreatedAt = %q, want %q", r.pk, r.sk, got, v)
		}
	}
}

func TestRunBackfillsEachRowType(t *testing.T) {
	w := newWorld(t)
	rep, err := Run(context.Background(), w.c, w.table, w.opts(false))
	if err != nil {
		t.Fatal(err)
	}
	w.assert(t, w.want)

	wantRemoved := map[string]int{"User": 1, "Recovery": 1, "UsernameClaim": 1, "Group": 1, "RoleGrant": 1}
	if !reflect.DeepEqual(rep.Removed, wantRemoved) {
		t.Errorf("Removed = %v, want %v", rep.Removed, wantRemoved)
	}
	// Kept: the test profile, the midnight membership and the admission.
	if rep.Truncated != 1 || rep.Kept != 3 || rep.Raced != 0 || rep.Scanned != 9 {
		t.Errorf("report = %+v, want Truncated 1, Kept 3, Raced 0, Scanned 9", rep)
	}
}

func TestRunIsIdempotent(t *testing.T) {
	w := newWorld(t)
	if _, err := Run(context.Background(), w.c, w.table, w.opts(false)); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), w.c, w.table, w.opts(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 || rep.Truncated != 0 || rep.Raced != 0 {
		t.Errorf("second run changed rows: %+v", rep)
	}
	w.assert(t, w.want)
}

func TestDryRunReportsTheSameAndWritesNothing(t *testing.T) {
	w := newWorld(t)
	before := map[row]string{}
	for _, r := range w.all {
		before[r] = created(t, w.c, w.table, r)
	}
	dry, err := Run(context.Background(), w.c, w.table, w.opts(true))
	if err != nil {
		t.Fatal(err)
	}
	// Nothing was written.
	for r, v := range before {
		if got := created(t, w.c, w.table, r); got != v {
			t.Errorf("%s/%s changed in a dry run: %q -> %q", r.pk, r.sk, v, got)
		}
	}
	real, err := Run(context.Background(), w.c, w.table, w.opts(false))
	if err != nil {
		t.Fatal(err)
	}
	dry.DryRun, real.DryRun = false, false
	if !reflect.DeepEqual(dry, real) {
		t.Errorf("dry report %+v differs from the real run's %+v", dry, real)
	}
}

// racing changes a row between the scan and the write: set is the update
// expression, vals its values.
type racing struct {
	API
	c     *dynamodb.Client
	table string
	r     row
	set   string
	vals  map[string]types.AttributeValue
	done  bool
}

func (a *racing) Scan(ctx context.Context, in *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	out, err := a.API.Scan(ctx, in, opts...)
	if err == nil && !a.done {
		a.done = true
		_, err = a.c.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 aws.String(a.table),
			Key:                       map[string]types.AttributeValue{"PK": s(a.r.pk), "SK": s(a.r.sk)},
			UpdateExpression:          aws.String(a.set),
			ExpressionAttributeValues: a.vals,
		})
	}
	return out, err
}

func TestRowChangedAfterTheScanIsLeftAlone(t *testing.T) {
	for _, tc := range []struct{ name, sk string }{{"PROFILE", "PROFILE"}, {"group META", "META"}} {
		t.Run(tc.name, func(t *testing.T) { rowChangedAfterTheScan(t, tc.sk) })
	}
}

func rowChangedAfterTheScan(t *testing.T, sk string) {
	w := newWorld(t)
	target := row{w.all[0].pk, sk}
	if sk == "META" {
		target = row{w.all[4].pk, sk}
	}
	rep, err := Run(context.Background(), &racing{API: w.c, c: w.c, table: w.table, r: target,
		set: "SET CreatedAt = :n", vals: map[string]types.AttributeValue{":n": s("2026-04-01T09:00:00Z")}}, w.table, w.opts(false))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Raced != 1 {
		t.Errorf("Raced = %d, want 1", rep.Raced)
	}
	if got := created(t, w.c, w.table, target); got != "2026-04-01T09:00:00Z" {
		t.Errorf("raced row CreatedAt = %q, want the concurrent writer's value", got)
	}
}

// A profile that becomes a test account after the scan keeps its CreatedAt
// even though that value is unchanged.
func TestProfileFlaggedAsTestAfterTheScanIsLeftAlone(t *testing.T) {
	w := newWorld(t)
	target := row{w.all[0].pk, "PROFILE"}
	api := &racing{API: w.c, c: w.c, table: w.table, r: target,
		set: "SET TestAccount = :t", vals: map[string]types.AttributeValue{":t": &types.AttributeValueMemberBOOL{Value: true}}}
	rep, err := Run(context.Background(), api, w.table, w.opts(false))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Raced != 1 {
		t.Errorf("Raced = %d, want 1", rep.Raced)
	}
	if got := created(t, w.c, w.table, target); got != fullRes {
		t.Errorf("CreatedAt = %q, want it kept (%q)", got, fullRes)
	}
}

func TestDecide(t *testing.T) {
	item := func(typ, created string, extra map[string]types.AttributeValue) map[string]types.AttributeValue {
		m := map[string]types.AttributeValue{"Type": s(typ)}
		if created != "" {
			m["CreatedAt"] = s(created)
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name string
		item map[string]types.AttributeValue
		want action
		day  string
	}{
		{"no CreatedAt", item("User", "", nil), keep, ""},
		{"real user", item("User", fullRes, nil), remove, ""},
		{"TestAccount false is real", item("User", fullRes, map[string]types.AttributeValue{"TestAccount": &types.AttributeValueMemberBOOL{Value: false}}), remove, ""},
		{"test user", item("User", fullRes, map[string]types.AttributeValue{"TestAccount": &types.AttributeValueMemberBOOL{Value: true}}), keep, ""},
		{"membership", item("Membership", fullRes, nil), truncate, dayRes},
		{"membership in a non-UTC offset", item("Membership", "2026-03-04T22:30:00-08:00", nil), truncate, "2026-03-05T00:00:00Z"},
		{"membership at midnight", item("Membership", dayRes, nil), keep, ""},
		{"membership unparseable", item("Membership", "not a time", nil), keep, ""},
		{"rotation", item("Rotation", fullRes, nil), keep, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, day := decide(tt.item)
			if got != tt.want || day != tt.day {
				t.Errorf("decide = (%v, %q), want (%v, %q)", got, day, tt.want, tt.day)
			}
		})
	}
}
