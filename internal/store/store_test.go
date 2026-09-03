package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminPassword(t *testing.T) {
	var a Admin
	if a.CheckPassword("anything") {
		t.Fatal("empty admin must not accept passwords")
	}
	if err := a.SetPassword("correct horse"); err != nil {
		t.Fatal(err)
	}
	if !a.CheckPassword("correct horse") || a.CheckPassword("wrong") {
		t.Fatal("password check failed")
	}
}

func TestOpenPersistsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	tok := NewClientToken()
	if err := s.Update(func(st *State) error {
		st.Clients = append(st.Clients, &Client{ID: NewID(), Name: "box", Token: tok})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	again.View(func(st *State) {
		if c := st.ClientByToken(tok); c == nil || c.Name != "box" {
			t.Fatalf("client not persisted: %+v", st.Clients)
		}
		if st.ClientByToken("") != nil || st.ClientByToken("sr_c_nope") != nil {
			t.Fatal("unexpected token match")
		}
	})
}

func TestForwardValidationAndConflicts(t *testing.T) {
	good := Forward{ID: "a", Name: "mc", Protocol: ProtoTCP, PublicPort: 25565, TargetHost: "127.0.0.1", TargetPort: 25565}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid forward rejected: %v", err)
	}
	bad := []Forward{
		{Name: "", Protocol: ProtoTCP, PublicPort: 1, TargetHost: "h", TargetPort: 1},
		{Name: "x", Protocol: "sctp", PublicPort: 1, TargetHost: "h", TargetPort: 1},
		{Name: "x", Protocol: ProtoTCP, PublicPort: 0, TargetHost: "h", TargetPort: 1},
		{Name: "x", Protocol: ProtoTCP, PublicPort: 1, TargetHost: "h", TargetPort: 70000},
		{Name: "x", Protocol: ProtoTCP, PublicPort: 1, TargetHost: "bad host", TargetPort: 1},
	}
	for i, f := range bad {
		if err := f.Validate(); !errors.Is(err, ErrValidation) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
	st := &State{Forwards: []*Forward{&good}}
	udp := Forward{ID: "b", Protocol: ProtoUDP, PublicPort: 25565}
	if st.PortConflict(&udp) != nil {
		t.Fatal("udp on a tcp port should not conflict")
	}
	both := Forward{ID: "c", Protocol: ProtoBoth, PublicPort: 25565}
	if st.PortConflict(&both) == nil {
		t.Fatal("both should conflict with existing tcp")
	}
	if st.PortConflict(&good) != nil {
		t.Fatal("a forward must not conflict with itself")
	}
}

func TestParsePortSpec(t *testing.T) {
	es, err := ParsePortSpec("7780-7784/UDP, 5673 15673\n25673>35673", ProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 8 {
		t.Fatalf("expected 8 entries, got %d: %+v", len(es), es)
	}
	if es[0] != (PortEntry{5673, ProtoTCP, 5673}) || es[1] != (PortEntry{7780, ProtoUDP, 7780}) || es[7] != (PortEntry{25673, ProtoTCP, 35673}) {
		t.Fatalf("unexpected expansion: %+v", es)
	}
	if got, want := RenderPortSpec(es), "5673/tcp, 7780-7784/udp, 15673/tcp, 25673/tcp>35673"; got != want {
		t.Fatalf("render: got %q want %q", got, want)
	}
	// Range with a target offset shifts every port.
	es, err = ParsePortSpec("2000-2002>3000", ProtoBoth)
	if err != nil {
		t.Fatal(err)
	}
	if es[2] != (PortEntry{2002, ProtoBoth, 3002}) {
		t.Fatalf("offset range: %+v", es)
	}
	if got := RenderPortSpec(es); got != "2000-2002/both>3000" {
		t.Fatalf("render offset range: %q", got)
	}
	// Same port on tcp and udp separately is allowed and renders separately.
	es, err = ParsePortSpec("27015/tcp, 27015/udp", ProtoTCP)
	if err != nil || len(es) != 2 {
		t.Fatalf("tcp+udp split: %v %+v", err, es)
	}
	if got := RenderPortSpec(es); got != "27015/tcp, 27015/udp" {
		t.Fatalf("render split: %q", got)
	}
}

func TestParsePortSpecRoundTrip(t *testing.T) {
	for _, spec := range []string{"25565/tcp", "5673/tcp, 7780-7784/udp, 15673/tcp, 25673/tcp", "1-3/both>10, 4/both>10", "100/tcp, 101/udp, 102/tcp"} {
		es, err := ParsePortSpec(spec, ProtoTCP)
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		if got := RenderPortSpec(es); got != spec {
			t.Fatalf("%q rendered as %q", spec, got)
		}
	}
}

func TestParsePortSpecRejects(t *testing.T) {
	bad := map[string]string{
		"":                  "required",
		"   ,  ":            "required",
		"7780-7784/tcpp":    "not valid",
		"abc":               "not valid",
		"0":                 "between 1 and 65535",
		"70000":             "between 1 and 65535",
		"7784-7780":         "greater than its end",
		"65530-65535>65533": "target ports",
		"5>0":               "target ports",
		"1-65535":           "more than 64",
		"1-64, 65":          "more than 64",
		"5673, 5673/both":   "more than once",
		"5673/both, 5673":   "more than once",
		"1-5/udp, 3/udp":    "more than once",
	}
	for spec, want := range bad {
		_, err := ParsePortSpec(spec, ProtoTCP)
		if err == nil || !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want validation error containing %q, got %v", spec, want, err)
		}
	}
	if _, err := ParsePortSpec("1-64", ProtoTCP); err != nil {
		t.Errorf("exactly 64 ports must be allowed: %v", err)
	}
	if _, err := ParsePortSpec("80", "icmp"); err == nil {
		t.Error("bad default protocol must be rejected")
	}
}

func TestOpenBackfillsGroupID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	legacy := `{"admin":{},"settings":{},"clients":[],"forwards":[{"id":"f1","client_id":"c","name":"a","protocol":"tcp","public_port":1,"target_host":"h","target_port":1,"enabled":true}],"tokens":[]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.View(func(s *State) {
		if got := s.ForwardByID("f1").GroupID; got != "f1" {
			t.Fatalf("group_id backfill: got %q", got)
		}
		if ids := s.GroupIDs(); len(ids) != 1 || ids[0] != "f1" {
			t.Fatalf("GroupIDs: %v", ids)
		}
	})
}
