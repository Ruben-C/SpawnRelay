package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payloads := [][]byte{[]byte("hello"), {}, bytes.Repeat([]byte{7}, MaxDatagram)}
	for _, p := range payloads {
		if err := WriteFrame(&buf, p); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := WriteFrame(&buf, make([]byte, MaxDatagram+1)); err == nil {
		t.Fatal("expected oversize datagram to be rejected")
	}
	scratch := make([]byte, MaxDatagram)
	for i, want := range payloads {
		got, err := ReadFrame(&buf, scratch)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: got %d bytes, want %d", i, len(got), len(want))
		}
	}
}

func TestJSONLine(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSONLine(&buf, Hello{Version: 1, Token: "sr_c_x"}); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("trailing payload")
	r := NewReader(&buf)
	var h Hello
	if err := ReadJSONLine(r, &h); err != nil {
		t.Fatal(err)
	}
	if h.Version != 1 || h.Token != "sr_c_x" {
		t.Fatalf("unexpected hello %+v", h)
	}
	rest := make([]byte, 32)
	n, _ := r.Read(rest)
	if string(rest[:n]) != "trailing payload" {
		t.Fatalf("payload after header was consumed: %q", rest[:n])
	}
}
