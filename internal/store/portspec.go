package store

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MaxGroupPorts caps how many public ports one port spec may expand to, so a
// typo like "1-65535" cannot open thousands of listeners and firewall rules.
const MaxGroupPorts = 64

// PortEntry is one expanded line of a port spec: a public port, the protocol
// it listens on and the port it is relayed to on the target host.
type PortEntry struct {
	PublicPort int
	Protocol   string
	TargetPort int
}

// entryRe matches PORT or START-END, an optional /proto and an optional >TARGET.
var entryRe = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?(?:/(tcp|udp|both))?(?:>(\d{1,5}))?$`)

// ParsePortSpec expands a port spec such as "7780-7784/udp, 5673, 15673>25673"
// into individual entries. Entries without a protocol suffix use defProto.
// Entries without a >TARGET target the same port number; for a range the
// target names the first port and the rest shift by the same offset.
func ParsePortSpec(spec, defProto string) ([]PortEntry, error) {
	switch defProto {
	case ProtoTCP, ProtoUDP, ProtoBoth:
	default:
		return nil, fmt.Errorf("%w: protocol must be tcp, udp or both", ErrValidation)
	}
	tokens := strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%w: ports is required", ErrValidation)
	}
	var out []PortEntry
	seen := map[int][]string{} // public port -> protocols already listed
	for _, raw := range tokens {
		tok := strings.ToLower(raw)
		m := entryRe.FindStringSubmatch(tok)
		if m == nil {
			return nil, fmt.Errorf("%w: port entry %q is not valid (expected PORT or START-END, optionally /tcp, /udp or /both, optionally >TARGET)", ErrValidation, raw)
		}
		start, _ := strconv.Atoi(m[1])
		end := start
		if m[2] != "" {
			end, _ = strconv.Atoi(m[2])
		}
		proto := m[3]
		if proto == "" {
			proto = defProto
		}
		target := start
		if m[4] != "" {
			target, _ = strconv.Atoi(m[4])
		}
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			return nil, fmt.Errorf("%w: port entry %q: ports must be between 1 and 65535", ErrValidation, raw)
		}
		if start > end {
			return nil, fmt.Errorf("%w: port entry %q: range start is greater than its end", ErrValidation, raw)
		}
		offset := target - start
		if target < 1 || end+offset > 65535 {
			return nil, fmt.Errorf("%w: port entry %q: target ports must be between 1 and 65535", ErrValidation, raw)
		}
		if len(out)+(end-start+1) > MaxGroupPorts {
			return nil, fmt.Errorf("%w: port spec expands to more than %d ports", ErrValidation, MaxGroupPorts)
		}
		for p := start; p <= end; p++ {
			for _, prev := range seen[p] {
				if protoOverlap(prev, proto) {
					return nil, fmt.Errorf("%w: port entry %q: port %d/%s is listed more than once", ErrValidation, raw, p, proto)
				}
			}
			seen[p] = append(seen[p], proto)
			out = append(out, PortEntry{PublicPort: p, Protocol: proto, TargetPort: p + offset})
		}
	}
	sortEntries(out)
	return out, nil
}

func protoOverlap(a, b string) bool {
	return a == b || a == ProtoBoth || b == ProtoBoth
}

func sortEntries(es []PortEntry) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && lessEntry(es[j], es[j-1]); j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}

func lessEntry(a, b PortEntry) bool {
	if a.PublicPort != b.PublicPort {
		return a.PublicPort < b.PublicPort
	}
	return a.Protocol < b.Protocol
}

// RenderPortSpec produces the canonical spec for entries: sorted by public
// port, contiguous runs with the same protocol and target offset collapsed
// into ranges, the protocol always shown and >TARGET only when it differs.
// ParsePortSpec(RenderPortSpec(e)) yields e again.
func RenderPortSpec(entries []PortEntry) string {
	es := append([]PortEntry(nil), entries...)
	sortEntries(es)
	var parts []string
	for i := 0; i < len(es); {
		j := i
		for j+1 < len(es) && es[j+1].PublicPort == es[j].PublicPort+1 && es[j+1].Protocol == es[i].Protocol &&
			es[j+1].TargetPort-es[j+1].PublicPort == es[i].TargetPort-es[i].PublicPort {
			j++
		}
		s := strconv.Itoa(es[i].PublicPort)
		if j > i {
			s += "-" + strconv.Itoa(es[j].PublicPort)
		}
		s += "/" + es[i].Protocol
		if es[i].TargetPort != es[i].PublicPort {
			s += ">" + strconv.Itoa(es[i].TargetPort)
		}
		parts = append(parts, s)
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

// Entry returns the port-spec view of a forward.
func (f *Forward) Entry() PortEntry {
	return PortEntry{PublicPort: f.PublicPort, Protocol: f.Protocol, TargetPort: f.TargetPort}
}

// GroupSpec renders the canonical port spec of a set of forwards.
func GroupSpec(fs []*Forward) string {
	es := make([]PortEntry, 0, len(fs))
	for _, f := range fs {
		es = append(es, f.Entry())
	}
	return RenderPortSpec(es)
}
