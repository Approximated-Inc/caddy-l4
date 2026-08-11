// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&retentionSentinel{})
}

// retentionSentinel is a test handler provisioned into a route that no test
// connection ever touches, so it is reachable only through the config
// generation's object graph (the caddy.Context's moduleInstances and the
// other server's compiled route). Its finalizer reports when the generation
// has become garbage.
type retentionSentinel struct {
	pad [64]byte //nolint:unused // real heap allocation so the finalizer is reliable
}

// sentinelFinalized is re-armed by the test before each provisioning; the
// finalizer closure captures the channel current at Provision time, so each
// instance closes its own channel exactly once (safe under -count>1).
var sentinelFinalized chan struct{}

func (*retentionSentinel) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.retention_sentinel",
		New: func() caddy.Module { return new(retentionSentinel) },
	}
}

func (s *retentionSentinel) Provision(_ caddy.Context) error {
	if ch := sentinelFinalized; ch != nil {
		runtime.SetFinalizer(s, func(*retentionSentinel) { close(ch) })
	}
	return nil
}

func (s *retentionSentinel) Handle(_ *layer4.Connection, _ layer4.Handler) error {
	return nil
}

// freeTCPAddr reserves an ephemeral port and releases it for the caller.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probing free port | %s", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// A proxied connection that outlives its config generation must not retain
// the generation: Handler keeps only the std context from Provision, so the
// caddy.Context (whose cfg/moduleInstances reach every module in the
// generation) becomes collectable as soon as the generation is stopped and
// unreferenced — even while the connection is still in flight. The grace
// period is set huge so the drain in App.Stop cannot mask retention by
// force-closing the connection.
func TestHandlerDoesNotRetainConfigGeneration(t *testing.T) {
	// backend that the proxy dials; accepted conns are held open
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen failed | %s", err)
	}
	defer func() { _ = backend.Close() }()
	backendConns := make(chan net.Conn, 1)
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			backendConns <- c
		}
	}()

	finalized := make(chan struct{})
	sentinelFinalized = finalized
	defer func() { sentinelFinalized = nil }()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()

	proxyAddr := freeTCPAddr(t)
	app := &layer4.App{
		GracePeriod: caddy.Duration(time.Hour), // drain must not close the conn
		Servers: map[string]*layer4.Server{
			"proxy": {
				Listen: []string{"tcp/" + proxyAddr},
				Routes: layer4.RouteList{&layer4.Route{
					HandlersRaw: []json.RawMessage{json.RawMessage(fmt.Sprintf(
						`{"handler":"proxy","upstreams":[{"dial":["%s"]}]}`, backend.Addr()))},
				}},
			},
			// never connected to; exists so the sentinel is reachable only
			// via the generation's object graph
			"sentinel": {
				Routes: layer4.RouteList{&layer4.Route{
					HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"retention_sentinel"}`)},
				}},
			},
		},
	}
	if err = app.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}
	if err = app.Start(); err != nil {
		t.Fatalf("start failed | %s", err)
	}

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial failed | %s", err)
	}
	defer func() { _ = client.Close() }()

	// prove the connection is genuinely proxied end to end
	roundTrip := func(payload string) {
		t.Helper()
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatalf("client write failed | %s", err)
		}
		var upstream net.Conn
		select {
		case upstream = <-backendConns:
			backendConns <- upstream
		case <-time.After(5 * time.Second):
			t.Fatal("proxy never dialed the backend")
		}
		buf := make([]byte, len(payload))
		_ = upstream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(upstream, buf); err != nil {
			t.Fatalf("backend read failed | %s", err)
		}
		if string(buf) != payload {
			t.Fatalf("backend got %q, want %q", buf, payload)
		}
	}
	roundTrip("ping")

	// negative control: generation still referenced -> sentinel must survive
	runtime.GC()
	runtime.GC()
	select {
	case <-finalized:
		t.Fatal("sentinel collected while the generation is still referenced; test harness is broken")
	default:
	}

	// simulate a config swap: stop and cancel the old generation while the
	// proxied connection stays in flight, then drop every test-held
	// reference to it
	if err = app.Stop(); err != nil {
		t.Fatalf("stop failed | %s", err)
	}
	cancel() // caddy cancels the old generation's context on config swap
	cancel = nil
	app = nil
	ctx = caddy.Context{}
	_ = ctx

	// the only remaining path to the sentinel would be: conn goroutine ->
	// Server -> compiledRoute -> Handler.ctx -> caddy.Context -> generation
	deadline := time.Now().Add(10 * time.Second)
	collected := false
	for !collected && time.Now().Before(deadline) {
		runtime.GC()
		select {
		case <-finalized:
			collected = true
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !collected {
		t.Fatal("config generation still retained while a proxied connection is in flight")
	}

	// the old generation's handler must still be proxying the live conn
	roundTrip("pong")
}
