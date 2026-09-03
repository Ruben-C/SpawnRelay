package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ruben-C/SpawnRelay/internal/store"
)

// freeRange finds n consecutive ports that are free for TCP and UDP.
func freeRange(t *testing.T, n int) int {
	t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		base := freePort(t)
		ok := true
		for p := base; p < base+n && ok; p++ {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				ok = false
				break
			}
			pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
			ln.Close()
			if err != nil {
				ok = false
				break
			}
			pc.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

type apiClient struct {
	t     *testing.T
	h     http.Handler
	token string
}

func newAPIClient(t *testing.T) (*apiClient, *Server) {
	t.Helper()
	s, err := New(Config{DataDir: t.TempDir(), TunnelAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0", PublicHost: "relay.test",
		Version: "test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.tunnel.Shutdown)
	token := store.NewAPIToken()
	if err := s.store.Update(func(st *store.State) error {
		st.Clients = append(st.Clients, &store.Client{ID: "c1", Name: "box"}, &store.Client{ID: "c2", Name: "other"})
		st.Tokens = append(st.Tokens, &store.APIToken{ID: "t1", Name: "test", TokenHash: store.HashToken(token)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return &apiClient{t: t, h: s.routes(), token: token}, s
}

func (c *apiClient) do(method, path string, body any, out any) (int, string) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			c.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: decode %v: %s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, rec.Body.String()
}

func (c *apiClient) mustDo(method, path string, body any, out any) {
	c.t.Helper()
	if code, resp := c.do(method, path, body, out); code >= 300 {
		c.t.Fatalf("%s %s: %d %s", method, path, code, resp)
	}
}

func TestForwardGroupLifecycle(t *testing.T) {
	c, s := newAPIClient(t)
	base := freeRange(t, 12)
	udp := fmt.Sprintf("%d-%d/udp", base, base+4)
	tcp := fmt.Sprintf("%d, %d, %d", base+5, base+6, base+7)

	// A2: a conflicting forward makes the whole create fail with nothing left behind.
	var single forwardOut
	c.mustDo("POST", "/api/v1/forwards", map[string]any{"client_id": "c1", "name": "Rabbit", "public_port": base + 6}, &single)
	if single.GroupID != single.ID {
		t.Fatalf("plain forward must be a group of one, got group_id %q", single.GroupID)
	}
	create := map[string]any{"client_id": "c1", "name": "Dune Awakening", "protocol": "tcp", "ports": udp + ", " + tcp, "target_host": "192.168.1.20"}
	code, resp := c.do("POST", "/api/v1/forward-groups", create, nil)
	if code != http.StatusConflict || !strings.Contains(resp, fmt.Sprint(base+6)) || !strings.Contains(resp, "Rabbit") {
		t.Fatalf("conflict: %d %s", code, resp)
	}
	var forwards []forwardOut
	c.mustDo("GET", "/api/v1/forwards", nil, &forwards)
	if len(forwards) != 1 {
		t.Fatalf("conflict must create nothing, have %d forwards", len(forwards))
	}
	c.mustDo("DELETE", "/api/v1/forwards/"+single.ID, nil, nil)

	// A1: create the group.
	var g groupOut
	c.mustDo("POST", "/api/v1/forward-groups", create, &g)
	if len(g.Forwards) != 8 || g.Name != "Dune Awakening" || g.TargetHost != "192.168.1.20" || !g.Enabled || !g.Stats.Listening {
		t.Fatalf("group: %+v", g)
	}
	if want := fmt.Sprintf("%s, %d-%d/tcp", udp, base+5, base+7); g.Ports != want {
		t.Fatalf("ports: got %q want %q", g.Ports, want)
	}
	for _, f := range g.Forwards {
		if f.GroupID != g.ID || f.TargetPort != f.PublicPort || f.TargetHost != "192.168.1.20" || !f.Stats.Listening {
			t.Fatalf("member: %+v", f)
		}
	}
	var status map[string]any
	c.mustDo("GET", "/api/v1/status", nil, &status)
	if status["forwards_total"].(float64) != 8 || status["forward_groups_total"].(float64) != 1 {
		t.Fatalf("status counts: %v", status)
	}
	var clients []clientOut
	c.mustDo("GET", "/api/v1/clients", nil, &clients)
	for _, cl := range clients {
		if cl.ID == "c1" && (cl.ForwardCount != 8 || cl.GroupCount != 1) {
			t.Fatalf("client counts: %+v", cl)
		}
	}
	var list []groupOut
	c.mustDo("GET", "/api/v1/forward-groups?client_id=c2", nil, &list)
	if len(list) != 0 {
		t.Fatalf("filter: %d", len(list))
	}

	// R11: a member cannot be moved to another client on its own.
	member := g.Forwards[0]
	if code, resp := c.do("PATCH", "/api/v1/forwards/"+member.ID, map[string]any{"client_id": "c2"}, nil); code != http.StatusBadRequest || !strings.Contains(resp, "group") {
		t.Fatalf("member move: %d %s", code, resp)
	}
	c.mustDo("PATCH", "/api/v1/forwards/"+member.ID, map[string]any{"name": "renamed"}, nil)

	// A3: extend the range; kept ports keep their ids.
	ids := map[string]string{}
	for _, f := range g.Forwards {
		ids[fmt.Sprintf("%d/%s", f.PublicPort, f.Protocol)] = f.ID
	}
	var g2 groupOut
	c.mustDo("PATCH", "/api/v1/forward-groups/"+g.ID, map[string]any{"ports": fmt.Sprintf("%d-%d/udp, %s", base, base+6, tcp), "name": "Dune"}, &g2)
	if len(g2.Forwards) != 10 || g2.Name != "Dune" {
		t.Fatalf("after extend: %d members, name %q", len(g2.Forwards), g2.Name)
	}
	for _, f := range g2.Forwards {
		if old, ok := ids[fmt.Sprintf("%d/%s", f.PublicPort, f.Protocol)]; ok && f.ID != old {
			t.Fatalf("port %d lost its id", f.PublicPort)
		}
		if f.Name != "Dune" {
			t.Fatalf("group rename must reach every member: %+v", f)
		}
	}
	if _, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", base+5)); err != nil {
		t.Fatalf("tcp listener missing after update: %v", err)
	}

	// A6: a bad spec changes nothing.
	if code, resp := c.do("PATCH", "/api/v1/forward-groups/"+g.ID, map[string]any{"ports": "1-65535"}, nil); code != http.StatusBadRequest || !strings.Contains(resp, "64") {
		t.Fatalf("oversize: %d %s", code, resp)
	}
	if code, resp := c.do("PATCH", "/api/v1/forward-groups/"+g.ID, map[string]any{"ports": ""}, nil); code != http.StatusBadRequest {
		t.Fatalf("empty: %d %s", code, resp)
	}
	// A bind failure on one new port rolls the whole change back.
	busy, err := net.Listen("tcp", fmt.Sprintf(":%d", base+9))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	code, resp = c.do("PATCH", "/api/v1/forward-groups/"+g.ID, map[string]any{"ports": fmt.Sprintf("%d-%d/udp, %s, %d", base, base+6, tcp, base+9)}, nil)
	if code != http.StatusConflict || !strings.Contains(resp, fmt.Sprint(base+9)) {
		t.Fatalf("bind failure: %d %s", code, resp)
	}
	var g3 groupOut
	c.mustDo("GET", "/api/v1/forward-groups/"+g.ID, nil, &g3)
	if g3.Ports != g2.Ports || !g3.Stats.Listening {
		t.Fatalf("rollback: %+v", g3)
	}

	// A4: disable, then delete.
	c.mustDo("PATCH", "/api/v1/forward-groups/"+g.ID, map[string]any{"enabled": false}, &g3)
	if g3.Enabled || g3.Stats.Listening {
		t.Fatalf("disable: %+v", g3)
	}
	for _, f := range g3.Forwards {
		if f.Enabled || f.Stats.Listening {
			t.Fatalf("member still enabled: %+v", f)
		}
	}
	if _, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", base+5)); err == nil {
		t.Fatal("listener still open after disable")
	}
	var del map[string]any
	c.mustDo("DELETE", "/api/v1/forward-groups/"+g.ID, nil, &del)
	if del["forwards_removed"].(float64) != 10 {
		t.Fatalf("delete: %v", del)
	}
	if code, _ := c.do("GET", "/api/v1/forward-groups/"+g.ID, nil, nil); code != http.StatusNotFound {
		t.Fatalf("deleted group still found: %d", code)
	}
	c.mustDo("GET", "/api/v1/forwards", nil, &forwards)
	if len(forwards) != 0 {
		t.Fatalf("members left behind: %d", len(forwards))
	}
	s.tunnel.mu.Lock()
	runners := len(s.tunnel.runners)
	s.tunnel.mu.Unlock()
	if runners != 0 {
		t.Fatalf("%d listeners left running", runners)
	}
}

func TestForwardGroupMemberDeleteShrinksGroup(t *testing.T) {
	c, _ := newAPIClient(t)
	base := freeRange(t, 2)
	var g groupOut
	c.mustDo("POST", "/api/v1/forward-groups", map[string]any{"client_id": "c1", "ports": fmt.Sprintf("%d-%d", base, base+1)}, &g)
	if g.Name != g.Ports || g.Ports != fmt.Sprintf("%d-%d/tcp", base, base+1) {
		t.Fatalf("default name/ports: %+v", g)
	}
	c.mustDo("DELETE", "/api/v1/forwards/"+g.Forwards[0].ID, nil, nil)
	c.mustDo("GET", "/api/v1/forward-groups/"+g.ID, nil, &g)
	if len(g.Forwards) != 1 || g.Ports != fmt.Sprintf("%d/tcp", base+1) {
		t.Fatalf("after member delete: %+v", g)
	}
	c.mustDo("DELETE", "/api/v1/forwards/"+g.Forwards[0].ID, nil, nil)
	if code, _ := c.do("GET", "/api/v1/forward-groups/"+g.ID, nil, nil); code != http.StatusNotFound {
		t.Fatalf("empty group must vanish: %d", code)
	}
}
