// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	bogo "github.com/google/boringssl/ssl/test/runner"
	"github.com/phuslu/net/http2"
)

func HTTP2(network, addr string, auth *Auth, forward Dialer, resolver Resolver) (Dialer, error) {
	var hostname string

	if host, _, err := net.SplitHostPort(addr); err == nil {
		hostname = host
	} else {
		hostname = addr
		addr = net.JoinHostPort(addr, "443")
	}

	s := &h2{
		network:  network,
		addr:     addr,
		hostname: hostname,
		forward:  forward,
		resolver: resolver,
	}
	if auth != nil {
		s.user = auth.User
		s.password = auth.Password
	}

	s.transport = &http2.Transport{
		DisableCompression: false,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			config := &bogo.Config{
				MinVersion:         cfg.MinVersion,
				MaxVersion:         bogo.VersionTLS13,
				NextProtos:         []string{"h2"},
				InsecureSkipVerify: cfg.InsecureSkipVerify,
				ServerName:         s.hostname,
				ClientSessionCache: bogo.NewLRUClientSessionCache(1024),
				MaxEarlyDataSize:   100 * 1024,
			}
			return bogo.Dial(s.network, s.addr, config)
		},
	}

	return s, nil
}

type h2 struct {
	user, password string
	network, addr  string
	hostname       string
	forward        Dialer
	resolver       Resolver
	transport      *http2.Transport
}

// Dial connects to the address addr on the network net via the HTTP1 proxy.
func (h *h2) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for HTTP proxy connections of type " + network)
	}

	pr, pw := io.Pipe()
	req := &http.Request{
		ProtoMajor: 2,
		Method:     http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   addr,
		},
		Host: addr,
		Header: http.Header{
			"Content-Type": []string{"application/octet-stream"},
			"User-Agent":   []string{"Mozilla/5.0"},
		},
		Body:          pr,
		ContentLength: -1,
	}

	if h.user != "" && h.password != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(h.user+":"+h.password)))
	}

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("proxy: failed to read greeting from HTTP proxy at " + h.addr + ": " + resp.Status)
	}

	conn := &http2Conn{
		r:      resp.Body,
		w:      pw,
		closed: make(chan struct{}),
	}

	return conn, nil
}

type http2Conn struct {
	r io.ReadCloser
	w io.Writer

	remoteAddr net.Addr
	localAddr  net.Addr

	closed chan struct{}
}

func (c *http2Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http2Conn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http2Conn) Close() (err error) {
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	if rc, ok := c.r.(io.Closer); ok {
		err = rc.Close()
	}
	if w, ok := c.w.(io.Closer); ok {
		err = w.Close()
	}
	return
}

func (c *http2Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http2Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http2Conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
