// Package relay contains the byte-shovelling helpers shared by the server and
// client sides of a tunnel.
package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// halfCloser is implemented by net.TCPConn and yamux streams (whose Close is a
// half-close: the peer sees EOF but may keep sending).
type halfCloser interface {
	CloseWrite() error
}

func closeWrite(c io.Closer) {
	if hc, ok := c.(halfCloser); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = c.Close()
}

// countingWriter adds every byte written to an optional live counter.
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if c.n != nil && n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// Pipe copies bidirectionally between a and b until both directions are done,
// propagating half-closes so that ordinary request/response protocols finish
// cleanly. It returns the bytes copied a->b and b->a.
func Pipe(a, b io.ReadWriteCloser) (aToB, bToA int64) {
	return PipeCounted(a, b, nil, nil)
}

// PipeCounted is Pipe with optional live counters that are updated as bytes
// flow, so callers can show traffic for long-lived connections.
func PipeCounted(a, b io.ReadWriteCloser, countAToB, countBToA *atomic.Int64) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aToB, _ = io.Copy(&countingWriter{b, countAToB}, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		bToA, _ = io.Copy(&countingWriter{a, countBToA}, b)
		closeWrite(a)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return aToB, bToA
}

// BufferedConn reads from r (typically a bufio.Reader that already consumed a
// header) but writes to and closes the underlying connection.
type BufferedConn struct {
	R io.Reader
	C io.ReadWriteCloser
}

func (b *BufferedConn) Read(p []byte) (int, error)  { return b.R.Read(p) }
func (b *BufferedConn) Write(p []byte) (int, error) { return b.C.Write(p) }
func (b *BufferedConn) Close() error                { return b.C.Close() }
func (b *BufferedConn) CloseWrite() error {
	if hc, ok := b.C.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return b.C.Close()
}

var _ halfCloser = (*net.TCPConn)(nil)
