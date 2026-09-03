package store

import (
	"errors"
	"path/filepath"
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
