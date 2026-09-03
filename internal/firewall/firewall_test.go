package firewall

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeRunner records commands and answers from a table keyed by the joined
// command line.
type fakeRunner struct {
	out   map[string]string
	fail  map[string]error
	calls []string
}

func (f *fakeRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if err, ok := f.fail[cmd]; ok {
		return "", err
	}
	return f.out[cmd], nil
}

func (f *fakeRunner) mutating() []string {
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, " status") || strings.Contains(c, " -S ") || strings.Contains(c, "list") || strings.Contains(c, "--state") {
			continue
		}
		out = append(out, c)
	}
	return out
}

const ufwSample = `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
25565/tcp                  ALLOW       Anywhere                   # spawnrelay:abc123
2456                       ALLOW       Anywhere
7777/udp                   ALLOW       10.0.0.0/8
8211/udp                   ALLOW       Anywhere                   # spawnrelay:old999
80/tcp                     ALLOW OUT   Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
25565/tcp (v6)             ALLOW       Anywhere (v6)              # spawnrelay:abc123
2456 (v6)                  ALLOW       Anywhere (v6)
8211/udp (v6)              ALLOW       Anywhere (v6)              # spawnrelay:old999
`

func TestParseUfwStatus(t *testing.T) {
	st := parseUfwStatus(ufwSample)
	if !st.active {
		t.Fatal("expected active")
	}
	wantTagged := map[string]string{"25565/tcp": "abc123", "8211/udp": "old999"}
	if !reflect.DeepEqual(st.tagged, wantTagged) {
		t.Fatalf("tagged = %v", st.tagged)
	}
	for _, k := range []string{"22/tcp", "2456/tcp", "2456/udp"} {
		if !st.untagged[k] {
			t.Errorf("expected untagged %s", k)
		}
	}
	if st.untagged["7777/udp"] || st.untagged["80/tcp"] {
		t.Errorf("source-restricted or outbound rules must not count: %v", st.untagged)
	}
}

func TestUfwSync(t *testing.T) {
	fr := &fakeRunner{out: map[string]string{"ufw status": ufwSample}}
	u := &ufw{run: fr.run}
	want := []Rule{
		{ID: "abc123", Port: 25565, Proto: "tcp"}, // already there
		{ID: "new111", Port: 2456, Proto: "udp"},  // operator rule covers it
		{ID: "new222", Port: 7777, Proto: "udp"},  // must be added (source-restricted rule doesn't count)
	}
	res, err := u.Sync(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Active || res.Backend != "ufw" {
		t.Fatalf("result = %+v", res)
	}
	if res.Rules["25565/tcp"].State != StateOpen || res.Rules["2456/udp"].State != StateExisting || res.Rules["7777/udp"].State != StateOpen {
		t.Fatalf("states = %+v", res.Rules)
	}
	got := fr.mutating()
	wantCalls := []string{
		"ufw allow 7777/udp comment spawnrelay:new222",
		"ufw delete allow 8211/udp comment spawnrelay:old999",
	}
	if !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("calls = %v", got)
	}
}

func TestUfwSyncError(t *testing.T) {
	fr := &fakeRunner{
		out:  map[string]string{"ufw status": "Status: inactive\n"},
		fail: map[string]error{"ufw allow 1234/tcp comment spawnrelay:x": errors.New("boom")},
	}
	res, err := (&ufw{run: fr.run}).Sync(context.Background(), []Rule{{ID: "x", Port: 1234, Proto: "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Active {
		t.Fatal("inactive ufw reported active")
	}
	if rs := res.Rules["1234/tcp"]; rs.State != StateError || !strings.Contains(rs.Error, "boom") {
		t.Fatalf("rule state = %+v", rs)
	}
}

const iptSample = `-P INPUT DROP
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 25565 -m comment --comment spawnrelay:abc123 -j ACCEPT
-A INPUT -p udp -m udp --dport 8211 -m comment --comment "spawnrelay:old999" -j ACCEPT
-A INPUT -s 10.0.0.0/8 -p udp -m udp --dport 7777 -j ACCEPT
`

func TestParseIptables(t *testing.T) {
	st := parseIptables(iptSample)
	if st.policy != "DROP" || !st.filtering() {
		t.Fatalf("policy = %q", st.policy)
	}
	if !reflect.DeepEqual(st.tagged, map[string]string{"25565/tcp": "abc123", "8211/udp": "old999"}) {
		t.Fatalf("tagged = %v", st.tagged)
	}
	if !st.untagged["22/tcp"] || st.untagged["7777/udp"] {
		t.Fatalf("untagged = %v", st.untagged)
	}
}

func TestIptablesSync(t *testing.T) {
	fr := &fakeRunner{out: map[string]string{"iptables -S INPUT": iptSample}}
	i := &iptables{run: fr.run, tools: []string{"iptables"}}
	want := []Rule{{ID: "abc123", Port: 25565, Proto: "tcp"}, {ID: "n", Port: 22, Proto: "tcp"}, {ID: "m", Port: 9000, Proto: "udp"}}
	res, err := i.Sync(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rules["25565/tcp"].State != StateOpen || res.Rules["22/tcp"].State != StateExisting || res.Rules["9000/udp"].State != StateOpen {
		t.Fatalf("states = %+v", res.Rules)
	}
	var got []string
	for _, c := range fr.calls {
		if strings.HasPrefix(c, "iptables -I") || strings.HasPrefix(c, "iptables -D") {
			got = append(got, c)
		}
	}
	wantCalls := []string{
		"iptables -D INPUT -p udp --dport 8211 -m comment --comment spawnrelay:old999 -j ACCEPT",
		"iptables -I INPUT -p udp --dport 9000 -m comment --comment spawnrelay:m -j ACCEPT",
	}
	if !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("calls = %v", got)
	}
}

const nftSample = `{"nftables": [
 {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
 {"table": {"family": "inet", "name": "filter", "handle": 1}},
 {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
 {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 10, "comment": "spawnrelay:abc123", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 25565}}, {"accept": null}]}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 11, "comment": "spawnrelay:old999", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 8211}}, {"accept": null}]}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 12, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"counter": {"packets": 1, "bytes": 2}}, {"accept": null}]}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 13, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 7777}}, {"accept": null}]}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 14, "expr": [{"drop": null}]}}
]}`

func TestNftablesSync(t *testing.T) {
	fr := &fakeRunner{out: map[string]string{"nft -j list ruleset": nftSample}}
	n := &nftables{run: fr.run}
	want := []Rule{{ID: "abc123", Port: 25565, Proto: "tcp"}, {ID: "n", Port: 22, Proto: "tcp"}, {ID: "m", Port: 7777, Proto: "udp"}}
	res, err := n.Sync(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Active {
		t.Fatal("expected active")
	}
	if res.Rules["25565/tcp"].State != StateOpen || res.Rules["22/tcp"].State != StateExisting || res.Rules["7777/udp"].State != StateOpen {
		t.Fatalf("states = %+v", res.Rules)
	}
	got := fr.mutating()
	wantCalls := []string{
		"nft delete rule inet filter input handle 11",
		`nft insert rule inet filter input udp dport 7777 accept comment "spawnrelay:m"`,
	}
	if !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("calls = %v", got)
	}
}

func TestNftablesDetectsIptablesChains(t *testing.T) {
	rs, err := parseNftRuleset(`{"nftables":[{"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input"}},{"chain":{"family":"ip6","table":"filter","name":"INPUT","type":"filter","hook":"input"}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !allIptablesChains(rs.inputChains()) {
		t.Fatal("expected iptables-nft chains to be recognised")
	}
	rs2, _ := parseNftRuleset(nftSample)
	if allIptablesChains(rs2.inputChains()) {
		t.Fatal("native nft chain misdetected as iptables")
	}
}

func TestFirewalldSync(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{out: map[string]string{
		"firewall-cmd --state":      "running\n",
		"firewall-cmd --list-ports": "22/tcp 25565/tcp 8211/udp\n",
	}}
	f := &firewalld{run: fr.run, ledger: filepath.Join(dir, "ledger.json")}
	if err := os.WriteFile(f.ledger, []byte(`{"firewalld":{"25565/tcp":"abc123","8211/udp":"old999"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []Rule{{ID: "abc123", Port: 25565, Proto: "tcp"}, {ID: "n", Port: 22, Proto: "tcp"}, {ID: "m", Port: 9000, Proto: "udp"}}
	res, err := f.Sync(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rules["25565/tcp"].State != StateOpen || res.Rules["22/tcp"].State != StateExisting || res.Rules["9000/udp"].State != StateOpen {
		t.Fatalf("states = %+v", res.Rules)
	}
	got := fr.mutating()
	wantCalls := []string{
		"firewall-cmd --add-port=9000/udp",
		"firewall-cmd --permanent --add-port=9000/udp",
		"firewall-cmd --remove-port=8211/udp",
		"firewall-cmd --permanent --remove-port=8211/udp",
	}
	if !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("calls = %v", got)
	}
	l, err := f.loadLedger()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(l.Firewalld, map[string]string{"25565/tcp": "abc123", "9000/udp": "m"}) {
		t.Fatalf("ledger = %v", l.Firewalld)
	}
}

type fakeBackend struct{ got []Rule }

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) Sync(ctx context.Context, want []Rule) (*Result, error) {
	f.got = want
	res := newResult("fake")
	res.Active = true
	for _, w := range want {
		res.set(w, StateOpen, nil)
	}
	return res, nil
}

func TestAgentRoundTrip(t *testing.T) {
	if os.Getenv("CI_NO_UNIX_SOCKETS") != "" {
		t.Skip()
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "fw.sock")
	fb := &fakeBackend{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, AgentConfig{
			Socket: sock, Version: "test", Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
			factory: func(ctx context.Context, mode string) (Backend, error) { return fb, nil },
		})
	}()
	for i := 0; i < 50 && !Available(sock); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !Available(sock) {
		t.Fatal("agent did not start")
	}
	rules := []Rule{{ID: "tunnel", Port: 7443, Proto: "tcp"}, {ID: "abc", Port: 25565, Proto: "tcp"}}
	resp, err := Sync(ctx, sock, ModeAuto, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Backend != "fake" || resp.Rules["25565/tcp"].State != StateOpen || resp.Version != "test" {
		t.Fatalf("resp = %+v", resp)
	}
	if !reflect.DeepEqual(fb.got, rules) {
		t.Fatalf("backend got %v", fb.got)
	}
	// Invalid input is rejected before reaching the backend.
	if _, err := Sync(ctx, sock, ModeAuto, []Rule{{ID: "bad id!", Port: 1, Proto: "tcp"}}); err == nil || !strings.Contains(err.Error(), "invalid rule id") {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := Sync(ctx, sock, ModeOff, nil); err == nil {
		t.Fatal("mode off must be rejected by the agent")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if Available(sock) {
		t.Fatal("socket not cleaned up")
	}
}
