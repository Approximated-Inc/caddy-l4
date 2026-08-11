package layer4

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(&testEchoHandler{})
}

// testEchoHandler is a terminal handler that echoes until the client
// closes, keeping the connection (and its handler goroutine) in flight.
type testEchoHandler struct{}

func (*testEchoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.test_echo",
		New: func() caddy.Module { return new(testEchoHandler) },
	}
}

func (h *testEchoHandler) Handle(cx *Connection, _ Handler) error {
	_, err := io.Copy(cx, cx)
	return err
}

// startEchoApp provisions and starts an App with one echo server on a
// random local port for the given network ("tcp" or "udp").
func startEchoApp(t *testing.T, network string, grace caddy.Duration) (*App, string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})

	app := &App{
		GracePeriod: grace,
		Servers: map[string]*Server{
			"test": {
				Listen: []string{network + "/127.0.0.1:0"},
				Routes: RouteList{&Route{
					HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"test_echo"}`)},
				}},
			},
		},
	}
	if err := app.Provision(ctx); err != nil {
		cancel()
		t.Fatalf("provision failed | %s", err)
	}
	if err := app.Start(); err != nil {
		cancel()
		t.Fatalf("start failed | %s", err)
	}

	var addr string
	if network == "udp" {
		addr = app.packetConns[0].LocalAddr().String()
	} else {
		addr = app.listeners[0].Addr().String()
	}
	return app, addr, cancel
}

// echoRoundTrip proves the server-side handler is up and running.
func echoRoundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed | %s", err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo read failed | %s", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
}

// waitDrained waits until all of the server's in-flight handlers are done.
func waitDrained(t *testing.T, s *Server, timeout time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	done := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return time.Since(start)
	case <-time.After(timeout):
		t.Fatalf("handlers still in flight after %s", timeout)
		return 0
	}
}

// A connection in flight when the app stops must be force-closed shortly
// after the grace period, and Stop itself must return promptly.
func TestStopForceClosesConnsAfterGrace(t *testing.T) {
	grace := 500 * time.Millisecond
	app, addr, cancel := startEchoApp(t, "tcp", caddy.Duration(grace))
	defer cancel()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed | %s", err)
	}
	defer func() { _ = conn.Close() }()
	echoRoundTrip(t, conn)

	start := time.Now()
	if err = app.Stop(); err != nil {
		t.Fatalf("stop failed | %s", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Stop blocked for %s", elapsed)
	}

	// the held connection should be closed by the server, but only after
	// the grace period has elapsed
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	elapsed := time.Since(start)
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection was not force-closed | err=%v", err)
	}
	if elapsed < grace-50*time.Millisecond {
		t.Fatalf("connection closed before the grace period: %s < %s", elapsed, grace)
	}
	if elapsed > grace+5*time.Second {
		t.Fatalf("connection closed too long after the grace period: %s", elapsed)
	}

	waitDrained(t, app.Servers["test"], 5*time.Second)
}

// Stop must return promptly even when the grace period is long and a
// connection is still in flight.
func TestStopReturnsPromptlyWithLongGrace(t *testing.T) {
	app, addr, cancel := startEchoApp(t, "tcp", caddy.Duration(time.Minute))
	defer cancel()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed | %s", err)
	}
	defer func() { _ = conn.Close() }()
	echoRoundTrip(t, conn)

	start := time.Now()
	if err = app.Stop(); err != nil {
		t.Fatalf("stop failed | %s", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Stop blocked for %s", elapsed)
	}

	// let the client finish naturally; the drain should complete well
	// before the one-minute grace period
	_ = conn.Close()
	if elapsed := waitDrained(t, app.Servers["test"], 10*time.Second); elapsed > 5*time.Second {
		t.Fatalf("drain took %s despite the connection having finished", elapsed)
	}
}

// A UDP association in flight at Stop must not deadlock and must finish
// promptly once the socket is closed.
func TestStopDrainsPacketConns(t *testing.T) {
	app, addr, cancel := startEchoApp(t, "udp", caddy.Duration(time.Minute))
	defer cancel()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial failed | %s", err)
	}
	defer func() { _ = conn.Close() }()
	echoRoundTrip(t, conn)

	start := time.Now()
	if err = app.Stop(); err != nil {
		t.Fatalf("stop failed | %s", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Stop blocked for %s", elapsed)
	}

	// closing the socket EOFs the association; no grace period needed
	if elapsed := waitDrained(t, app.Servers["test"], 10*time.Second); elapsed > 5*time.Second {
		t.Fatalf("packet conn drain took %s", elapsed)
	}
}

// Stop must be safe on an app that was provisioned but never started.
func TestStopWithoutStart(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	app := &App{Servers: map[string]*Server{"test": {Listen: []string{"tcp/127.0.0.1:0"}}}}
	if err := app.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}
	if err := app.Stop(); err != nil {
		t.Fatalf("stop failed | %s", err)
	}
	waitDrained(t, app.Servers["test"], 5*time.Second)
}

// The listener-wrapper path (which has its own lifecycle) must keep
// working: wrapped connections are still piped through Accept.
func TestListenerWrapperStillServes(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	lw := &ListenerWrapper{}
	if err := lw.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed | %s", err)
	}
	wrapped := lw.WrapListener(ln)
	defer func() { _ = wrapped.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed | %s", err)
	}
	defer func() { _ = client.Close() }()
	if _, err = client.Write([]byte("hello")); err != nil {
		t.Fatalf("write failed | %s", err)
	}

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("accept failed | %s", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read failed | %s", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("unexpected payload %q", buf)
	}
}
