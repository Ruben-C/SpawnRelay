package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/firewall"
	"github.com/Ruben-C/SpawnRelay/internal/store"
)

// A forward group is the set of forwards created from one port spec. There is
// no stored group record: the members share a group_id, and group-level
// fields (client, name, target host, enabled) are written to every member.

type groupOut struct {
	ID         string          `json:"id"`
	ClientID   string          `json:"client_id"`
	ClientName string          `json:"client_name"`
	Name       string          `json:"name"`
	Protocol   string          `json:"protocol"`
	Ports      string          `json:"ports"`
	TargetHost string          `json:"target_host"`
	Enabled    bool            `json:"enabled"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	PublicHost string          `json:"public_host"`
	Stats      ForwardStats    `json:"stats"`
	Firewall   ForwardFirewall `json:"firewall"`
	Forwards   []forwardOut    `json:"forwards"`
}

// fwSeverity orders per-forward firewall states so a group can report the
// worst one among its enabled members.
func fwSeverity(state string) int {
	switch state {
	case firewall.StateError:
		return 5
	case firewall.StateExisting:
		return 3
	case firewall.StateOpen:
		return 2
	case fwUnmanaged, fwNone:
		return 1
	default: // closed
		return 0
	}
}

// groupOut aggregates the (sorted, non-empty) members of one group.
func (s *Server) groupOut(st *store.State, members []*store.Forward) groupOut {
	first := members[0]
	out := groupOut{
		ID: first.GroupID, ClientID: first.ClientID, Name: first.Name, Protocol: first.Protocol,
		Ports: store.GroupSpec(members), TargetHost: first.TargetHost, Enabled: true,
		CreatedAt: first.CreatedAt, UpdatedAt: first.UpdatedAt, PublicHost: s.PublicHost(),
		Stats: ForwardStats{Listening: true}, Firewall: ForwardFirewall{State: fwClosed},
	}
	if c := st.ClientByID(first.ClientID); c != nil {
		out.ClientName = c.Name
	}
	enabledMembers := 0
	for _, f := range members {
		fo := s.forwardOut(st, f)
		out.Forwards = append(out.Forwards, fo)
		if f.CreatedAt.Before(out.CreatedAt) {
			out.CreatedAt = f.CreatedAt
		}
		if f.UpdatedAt.After(out.UpdatedAt) {
			out.UpdatedAt = f.UpdatedAt
		}
		if !f.Enabled {
			out.Enabled = false
		} else {
			enabledMembers++
			if !fo.Stats.Listening {
				out.Stats.Listening = false
				if out.Stats.Error == "" {
					out.Stats.Error = fo.Stats.Error
				}
			}
			if fwSeverity(fo.Firewall.State) > fwSeverity(out.Firewall.State) {
				out.Firewall = fo.Firewall
			}
		}
		out.Stats.ActiveTCP += fo.Stats.ActiveTCP
		out.Stats.ActiveUDP += fo.Stats.ActiveUDP
		out.Stats.TotalConnections += fo.Stats.TotalConnections
		out.Stats.BytesIn += fo.Stats.BytesIn
		out.Stats.BytesOut += fo.Stats.BytesOut
	}
	if enabledMembers == 0 {
		out.Stats.Listening = false
		// A disabled group still reports "unmanaged"/"none" when that is the global situation.
		out.Firewall = s.firewall.ForwardState(first)
	}
	return out
}

type groupInput struct {
	ClientID   *string `json:"client_id"`
	Name       *string `json:"name"`
	Protocol   *string `json:"protocol"`
	Ports      *string `json:"ports"`
	TargetHost *string `json:"target_host"`
	Enabled    *bool   `json:"enabled"`
}

// groupFields are the group-level values shared by every member.
type groupFields struct {
	ClientID, Name, Protocol, Ports, TargetHost string
	Enabled                                     bool
}

func (in *groupInput) applyTo(g *groupFields) {
	if in.ClientID != nil {
		g.ClientID = strings.TrimSpace(*in.ClientID)
	}
	if in.Name != nil {
		g.Name = strings.TrimSpace(*in.Name)
	}
	if in.Protocol != nil {
		g.Protocol = strings.ToLower(strings.TrimSpace(*in.Protocol))
	}
	if in.Ports != nil {
		g.Ports = *in.Ports
	}
	if in.TargetHost != nil {
		g.TargetHost = strings.TrimSpace(*in.TargetHost)
	}
	if in.Enabled != nil {
		g.Enabled = *in.Enabled
	}
}

// groupPortConflict is PortConflict ignoring every member of groupID, so a
// group may reshuffle its own ports freely.
func groupPortConflict(st *store.State, groupID string, f *store.Forward) *store.Forward {
	for _, o := range st.Forwards {
		if o.GroupID == groupID || o.PublicPort != f.PublicPort {
			continue
		}
		if (f.HasTCP() && o.HasTCP()) || (f.HasUDP() && o.HasUDP()) {
			return o
		}
	}
	return nil
}

// expandGroup turns g into member forwards, reusing the ids of prev members
// with the same (public port, protocol) so their stats survive an edit.
func (s *Server) expandGroup(groupID string, g groupFields, prev []*store.Forward, now time.Time) ([]*store.Forward, error) {
	entries, err := store.ParsePortSpec(g.Ports, g.Protocol)
	if err != nil {
		return nil, err
	}
	if g.Name == "" {
		g.Name = store.RenderPortSpec(entries)
	}
	if err := store.ValidateName(g.Name); err != nil {
		return nil, err
	}
	prevByKey := map[[2]string]*store.Forward{}
	for _, f := range prev {
		prevByKey[[2]string{fmt.Sprint(f.PublicPort), f.Protocol}] = f
	}
	var members []*store.Forward
	for _, e := range entries {
		f := &store.Forward{ID: store.NewID(), GroupID: groupID, CreatedAt: now}
		if old := prevByKey[[2]string{fmt.Sprint(e.PublicPort), e.Protocol}]; old != nil {
			f.ID, f.CreatedAt = old.ID, old.CreatedAt
		}
		f.ClientID, f.Name, f.TargetHost, f.Enabled, f.UpdatedAt = g.ClientID, g.Name, g.TargetHost, g.Enabled, now
		f.PublicPort, f.Protocol, f.TargetPort = e.PublicPort, e.Protocol, e.TargetPort
		if err := f.Validate(); err != nil {
			return nil, err
		}
		if err := s.reservedPort(f.PublicPort); err != nil {
			return nil, err
		}
		members = append(members, f)
	}
	return members, nil
}

// commitGroup checks conflicts, binds listeners and swaps the members of
// groupID in st. Nothing changes unless every step succeeds.
func (s *Server) commitGroup(st *store.State, groupID string, next, prev []*store.Forward) error {
	if st.ClientByID(next[0].ClientID) == nil {
		return fmt.Errorf("%w: client_id does not refer to an existing client", store.ErrValidation)
	}
	for _, f := range next {
		if o := groupPortConflict(st, groupID, f); o != nil {
			return fmt.Errorf("%w: port %d is already used by forward %q", store.ErrConflict, f.PublicPort, o.Name)
		}
	}
	if err := s.tunnel.ApplyGroup(next, prev); err != nil {
		return fmt.Errorf("%w: cannot listen on %v", store.ErrConflict, err)
	}
	nextByID := map[string]*store.Forward{}
	for _, f := range next {
		nextByID[f.ID] = f
	}
	kept := st.Forwards[:0]
	for _, o := range st.Forwards {
		if o.GroupID != groupID {
			kept = append(kept, o)
		} else if n := nextByID[o.ID]; n != nil {
			kept = append(kept, n)
			delete(nextByID, o.ID)
		}
	}
	for _, f := range next {
		if nextByID[f.ID] != nil {
			kept = append(kept, f)
		}
	}
	st.Forwards = kept
	return nil
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("client_id")
	out := []groupOut{}
	s.store.View(func(st *store.State) {
		for _, id := range st.GroupIDs() {
			members := st.ForwardsInGroup(id)
			if filter != "" && members[0].ClientID != filter {
				continue
			}
			out = append(out, s.groupOut(st, members))
		}
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var out *groupOut
	s.store.View(func(st *store.State) {
		if members := st.ForwardsInGroup(id); len(members) > 0 {
			o := s.groupOut(st, members)
			out = &o
		}
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "forward group not found")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var in groupInput
	if !readJSON(w, r, &in) {
		return
	}
	g := groupFields{Protocol: store.ProtoTCP, TargetHost: "127.0.0.1", Enabled: true}
	in.applyTo(&g)
	groupID := store.NewID()
	members, err := s.expandGroup(groupID, g, nil, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var out groupOut
	err = s.store.Update(func(st *store.State) error {
		if err := s.commitGroup(st, groupID, members, nil); err != nil {
			return err
		}
		out = s.groupOut(st, members)
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.tunnel.NotifyForwards(g.ClientID)
	s.firewall.Sync(r.Context())
	s.store.View(func(st *store.State) { out = s.groupOut(st, st.ForwardsInGroup(groupID)) })
	s.log.Info("forward group created", "group", out.Name, "ports", out.Ports, "target_host", out.TargetHost, "by", principalFrom(r).Name)
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in groupInput
	if !readJSON(w, r, &in) {
		return
	}
	var out groupOut
	var oldClient string
	err := s.store.Update(func(st *store.State) error {
		prev := st.ForwardsInGroup(id)
		if len(prev) == 0 {
			return fmt.Errorf("%w: forward group not found", store.ErrNotFound)
		}
		cur := s.groupOut(st, prev)
		// The canonical spec carries a protocol on every entry, so the
		// default only matters for suffix-less entries in a new spec, where
		// it is tcp unless the request says otherwise (same as create).
		g := groupFields{ClientID: cur.ClientID, Name: cur.Name, Protocol: store.ProtoTCP, Ports: cur.Ports, TargetHost: cur.TargetHost, Enabled: cur.Enabled}
		in.applyTo(&g)
		next, err := s.expandGroup(id, g, prev, time.Now())
		if err != nil {
			return err
		}
		if err := s.commitGroup(st, id, next, prev); err != nil {
			return err
		}
		oldClient = cur.ClientID
		out = s.groupOut(st, next)
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.tunnel.NotifyForwards(out.ClientID)
	if oldClient != out.ClientID {
		s.tunnel.NotifyForwards(oldClient)
	}
	s.firewall.Sync(r.Context())
	s.store.View(func(st *store.State) { out = s.groupOut(st, st.ForwardsInGroup(id)) })
	s.log.Info("forward group updated", "group", out.Name, "ports", out.Ports, "target_host", out.TargetHost, "enabled", out.Enabled, "by", principalFrom(r).Name)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var removed []*store.Forward
	err := s.store.Update(func(st *store.State) error {
		removed = st.ForwardsInGroup(id)
		if len(removed) == 0 {
			return fmt.Errorf("%w: forward group not found", store.ErrNotFound)
		}
		kept := st.Forwards[:0]
		for _, o := range st.Forwards {
			if o.GroupID != id {
				kept = append(kept, o)
			}
		}
		st.Forwards = kept
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, f := range removed {
		s.tunnel.Remove(f.ID)
	}
	s.tunnel.NotifyForwards(removed[0].ClientID)
	s.firewall.Sync(r.Context())
	s.log.Info("forward group deleted", "group", removed[0].Name, "ports", store.GroupSpec(removed), "by", principalFrom(r).Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "forwards_removed": len(removed)})
}
