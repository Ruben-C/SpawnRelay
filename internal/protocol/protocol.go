// Package protocol defines the wire format spoken between the SpawnRelay
// server and its clients.
//
// A client opens a single TLS connection to the server's tunnel port and runs
// a yamux session over it. The first stream the client opens is the control
// stream: the client sends a Hello, the server answers with a HelloResponse,
// and afterwards the server pushes newline-delimited ControlMessages. The
// client may send ControlMessages of its own on the same stream (update
// progress); the server ignores types it does not know.
//
// The client may also open streams towards the server: the first line is a
// ClientRequest. The only request today is "download", which fetches a
// client binary for self-update; the server answers with a DownloadResponse
// line followed by the raw file.
//
// For every connection that reaches a public port on the server, the server
// opens a new yamux stream to the client, writes a single StreamHeader line,
// and then relays raw bytes (TCP) or length-prefixed datagrams (UDP).
package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version; bumped only on incompatible changes.
const Version = 1

// Maximum size of a single JSON control line.
const maxLine = 64 * 1024

// MaxDatagram is the largest UDP payload relayed over a stream.
const MaxDatagram = 65535

// Hello is sent by the client on the control stream right after connecting.
type Hello struct {
	Version       int    `json:"version"`
	Token         string `json:"token"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	ClientVersion string `json:"client_version"`
	AllowUpdate   bool   `json:"allow_update,omitempty"` // the client will install updates pushed by the server
}

// HelloResponse is the server's answer to Hello.
type HelloResponse struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	ClientName    string `json:"client_name,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
}

// ControlMessage is exchanged on the control stream. Server to client:
// "forwards", "shutdown", "update". Client to server: "update_status".
type ControlMessage struct {
	Type     string        `json:"type"`
	Message  string        `json:"message,omitempty"`
	Forwards []ForwardInfo `json:"forwards,omitempty"`
	Update   *UpdateInfo   `json:"update,omitempty"` // with type "update"
	Status   string        `json:"status,omitempty"` // with type "update_status": downloading | installing | restarting | failed
}

// UpdateInfo tells the client which binary to fetch and what to expect.
type UpdateInfo struct {
	Version string `json:"version"` // version the new binary must report
	Name    string `json:"name"`    // asset name, e.g. spawnrelay_linux_amd64
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"` // hex
}

// ClientRequest is the first line of a stream the client opens to the server.
type ClientRequest struct {
	Type string `json:"type"` // "download"
	Name string `json:"name,omitempty"`
}

// DownloadResponse precedes the file bytes on a download stream.
type DownloadResponse struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// ForwardInfo describes one port forward, for the client's information/logs.
type ForwardInfo struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	PublicPort int    `json:"public_port"`
	Target     string `json:"target"`
}

// StreamHeader is the first line written by the server on every data stream.
type StreamHeader struct {
	Type      string `json:"type"` // "tcp" | "udp"
	ForwardID string `json:"forward_id"`
	Target    string `json:"target"` // host:port on the client side
	Remote    string `json:"remote"` // address of the remote peer (informational)
}

// WriteJSONLine encodes v as a single JSON line.
func WriteJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// ReadJSONLine reads one JSON line from r into v.
func ReadJSONLine(r *bufio.Reader, v any) error {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return fmt.Errorf("protocol: line exceeds %d bytes", maxLine)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// NewReader returns a bufio.Reader sized for control lines.
func NewReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, maxLine)
}

// WriteFrame writes one UDP datagram as a 2-byte big-endian length prefix
// followed by the payload.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxDatagram {
		return fmt.Errorf("protocol: datagram too large (%d bytes)", len(payload))
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	copy(buf[2:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one datagram into buf (which must be at least MaxDatagram
// bytes) and returns the payload slice.
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		return nil, fmt.Errorf("protocol: frame of %d bytes exceeds buffer", n)
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}
