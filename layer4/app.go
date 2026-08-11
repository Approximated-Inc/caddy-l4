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

package layer4

import (
	"fmt"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&App{})
}

// App is a Caddy app that operates closest to layer 4 of the OSI model.
type App struct {
	// Servers are the servers to create. The key of each server must be
	// a unique name identifying the server for your own convenience;
	// the order of servers does not matter.
	Servers map[string]*Server `json:"servers,omitempty"`

	// GracePeriod is how long in-flight connections get to finish after
	// the app stops (e.g. on a config reload) before they are
	// force-closed. Connections that outlive a reload keep the old
	// config generation in memory, so retention is bounded by this.
	// Default: 30s.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	listeners   []net.Listener
	packetConns []net.PacketConn
	logger      *zap.Logger
	ctx         caddy.Context
}

// CaddyModule returns the Caddy module information.
func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()

	if a.GracePeriod <= 0 {
		a.GracePeriod = caddy.Duration(GracePeriodDefault)
	}

	for srvName, srv := range a.Servers {
		err := srv.Provision(ctx, a.logger)
		if err != nil {
			return fmt.Errorf("server '%s': %v", srvName, err)
		}
	}

	return nil
}

// Start starts the app.
func (a *App) Start() error {
	for _, s := range a.Servers {
		for _, addr := range s.listenAddrs {
			listeners, err := addr.ListenAll(a.ctx, net.ListenConfig{})
			if err != nil {
				return err
			}
			for _, lnAny := range listeners {
				switch ln := lnAny.(type) {
				case net.Listener:
					a.listeners = append(a.listeners, ln)
					go func(s *Server, ln net.Listener) {
						s.logger.Debug("started handling listener socket",
							zap.String("network", ln.Addr().Network()),
							zap.String("address", ln.Addr().String()),
						)
						err := s.serve(ln)
						s.logger.Debug("stopped handling listener socket",
							zap.String("network", ln.Addr().Network()),
							zap.String("address", ln.Addr().String()),
							zap.Error(err),
						)
					}(s, ln)
				case net.PacketConn:
					a.packetConns = append(a.packetConns, ln)
					go func(s *Server, pc net.PacketConn) {
						s.logger.Debug("started handling packet connection socket",
							zap.String("network", ln.LocalAddr().Network()),
							zap.String("address", ln.LocalAddr().String()),
						)
						err := s.servePacket(pc)
						s.logger.Debug("stopped handling packet connection socket",
							zap.String("network", pc.LocalAddr().Network()),
							zap.String("address", pc.LocalAddr().String()),
							zap.Error(err),
						)
					}(s, ln)
				}
			}
		}
	}
	return nil
}

// Stop stops the servers, closes all listeners, and drains in-flight
// connections: they get up to GracePeriod to finish before being
// force-closed, so they cannot pin the old config generation forever.
func (a *App) Stop() error {
	for _, pc := range a.packetConns {
		err := pc.Close()
		if err != nil {
			a.logger.Error("closing packet connection socket",
				zap.String("network", pc.LocalAddr().Network()),
				zap.String("address", pc.LocalAddr().String()),
				zap.Error(err),
			)
		}
	}
	for _, ln := range a.listeners {
		err := ln.Close()
		if err != nil {
			a.logger.Error("closing listener socket",
				zap.String("network", ln.Addr().Network()),
				zap.String("address", ln.Addr().String()),
				zap.Error(err),
			)
		}
	}
	// drain asynchronously so config reloads are not delayed by the
	// grace period; retention stays bounded either way
	for _, s := range a.Servers {
		go s.drainConns(time.Duration(a.GracePeriod))
	}
	return nil
}

// Interface guard
var _ caddy.App = (*App)(nil)
