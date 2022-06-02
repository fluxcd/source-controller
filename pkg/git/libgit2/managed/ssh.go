/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
This was inspired and contains part of:
https://github.com/libgit2/git2go/blob/eae00773cce87d5282a8ac7c10b5c1961ee6f9cb/ssh.go

The MIT License

Copyright (c) 2013 The git2go contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package managed

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"

	"github.com/fluxcd/source-controller/pkg/git"
	git2go "github.com/libgit2/git2go/v33"
)

// registerManagedSSH registers a Go-native implementation of
// SSH transport that doesn't rely on any lower-level libraries
// such as libssh2.
func registerManagedSSH() error {
	for _, protocol := range []string{"ssh", "ssh+git", "git+ssh"} {
		_, err := git2go.NewRegisteredSmartTransport(protocol, false, sshSmartSubtransportFactory)
		if err != nil {
			return fmt.Errorf("failed to register transport for %q: %v", protocol, err)
		}
	}
	return nil
}

func sshSmartSubtransportFactory(remote *git2go.Remote, transport *git2go.Transport) (git2go.SmartSubtransport, error) {
	return &sshSmartSubtransport{
		transport: transport,
	}, nil
}

type sshSmartSubtransport struct {
	transport *git2go.Transport

	lastAction git2go.SmartServiceAction
	stdin      io.WriteCloser
	stdout     io.Reader
	addr       string
	ctx        context.Context

	con connection
}

type connection struct {
	conn          net.Conn
	client        *ssh.Client
	session       *ssh.Session
	currentStream *sshSmartSubtransportStream
	connected     bool
	m             sync.Mutex
}

func (t *sshSmartSubtransport) Action(transportOptionsURL string, action git2go.SmartServiceAction) (git2go.SmartSubtransportStream, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	opts, found := getTransportOptions(transportOptionsURL)
	if !found {
		return nil, fmt.Errorf("could not find transport options for object: %s", transportOptionsURL)
	}

	t.ctx = opts.Context

	u, err := url.Parse(opts.TargetURL)
	if err != nil {
		return nil, err
	}

	if len(u.Path) > PathMaxLength {
		return nil, fmt.Errorf("path exceeds the max length (%d)", PathMaxLength)
	}

	// decode URI's path
	uPath, err := url.PathUnescape(u.Path)
	if err != nil {
		return nil, err
	}

	// Escape \ and '.
	uPath = strings.Replace(uPath, `\`, `\\`, -1)
	uPath = strings.Replace(uPath, `'`, `\'`, -1)

	var cmd string
	switch action {
	case git2go.SmartServiceActionUploadpackLs, git2go.SmartServiceActionUploadpack:
		if t.con.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionUploadpackLs {
				return t.con.currentStream, nil
			}
		}
		cmd = fmt.Sprintf("git-upload-pack '%s'", uPath)

	case git2go.SmartServiceActionReceivepackLs, git2go.SmartServiceActionReceivepack:
		if t.con.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionReceivepackLs {
				return t.con.currentStream, nil
			}
		}
		cmd = fmt.Sprintf("git-receive-pack '%s'", uPath)

	default:
		return nil, fmt.Errorf("unexpected action: %v", action)
	}

	if t.con.connected {
		// Disregard errors from previous stream, futher details inside Close().
		_ = t.Close()
	}

	port := "22"
	if u.Port() != "" {
		port = u.Port()
	}
	t.addr = net.JoinHostPort(u.Hostname(), port)

	sshConfig, err := createClientConfig(opts.AuthOpts)
	if err != nil {
		return nil, err
	}

	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		marshaledKey := key.Marshal()
		cert := &git2go.Certificate{
			Kind: git2go.CertificateHostkey,
			Hostkey: git2go.HostkeyCertificate{
				Kind:         git2go.HostkeySHA256 | git2go.HostkeyRaw,
				HashSHA256:   sha256.Sum256(marshaledKey),
				Hostkey:      marshaledKey,
				SSHPublicKey: key,
			},
		}

		if len(opts.AuthOpts.KnownHosts) > 0 {
			return KnownHostsCallback(hostname, opts.AuthOpts.KnownHosts)(cert, true, hostname)
		}
		return nil
	}

	err = t.createConn(t.addr, sshConfig)
	if err != nil {
		return nil, err
	}
	t.con.m.Lock()
	t.con.connected = true
	t.con.m.Unlock()

	traceLog.Info("[ssh]: creating new ssh session")
	if t.con.session, err = t.con.client.NewSession(); err != nil {
		return nil, err
	}

	if t.stdin, err = t.con.session.StdinPipe(); err != nil {
		return nil, err
	}

	var w *io.PipeWriter
	var reader io.Reader
	t.stdout, w = io.Pipe()
	if reader, err = t.con.session.StdoutPipe(); err != nil {
		return nil, err
	}

	// If the session's stdout pipe is not serviced fast
	// enough it may cause the remote command to block.
	//
	// xref: https://github.com/golang/crypto/blob/eb4f295cb31f7fb5d52810411604a2638c9b19a2/ssh/session.go#L553-L558
	go func() error {
		defer func() {
			w.Close()

			// In case this goroutine panics, handle recovery.
			if r := recover(); r != nil {
				traceLog.Error(errors.New(r.(string)),
					"[ssh]: recovered from libgit2 ssh smart subtransport panic", "address", t.addr)
			}
		}()

		var cancel context.CancelFunc
		ctx := t.ctx

		// When context is nil, creates a new with internal SSH connection timeout.
		if ctx == nil {
			ctx, cancel = context.WithTimeout(context.Background(), sshConnectionTimeOut)
			defer cancel()
		}

		for {
			select {
			case <-ctx.Done():
				t.Close()
				return nil

			default:
				t.con.m.Lock()
				if !t.con.connected {
					t.con.m.Unlock()
					return nil
				}
				t.con.m.Unlock()

				_, err := io.Copy(w, reader)
				if err != nil {
					return err
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	traceLog.Info("[ssh]: run on remote", "cmd", cmd)
	if err := t.con.session.Start(cmd); err != nil {
		return nil, err
	}

	t.lastAction = action
	t.con.currentStream = &sshSmartSubtransportStream{
		owner: t,
	}

	return t.con.currentStream, nil
}

func (t *sshSmartSubtransport) createConn(addr string, sshConfig *ssh.ClientConfig) error {
	ctx, cancel := context.WithTimeout(context.TODO(), sshConnectionTimeOut)
	defer cancel()

	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		return err
	}

	t.con.conn = conn
	t.con.client = ssh.NewClient(c, chans, reqs)

	return nil
}

// Close closes the smart subtransport.
//
// This is called internally ahead of a new action, and also
// upstream by the transport handler:
// https://github.com/libgit2/git2go/blob/0e8009f00a65034d196c67b1cdd82af6f12c34d3/transport.go#L409
//
// Avoid returning errors, but focus on releasing anything that
// may impair the transport to have successful actions on a new
// SmartSubTransport (i.e. unreleased resources, staled connections).
func (t *sshSmartSubtransport) Close() error {
	traceLog.Info("[ssh]: sshSmartSubtransport.Close()", "server", t.addr)
	t.con.m.Lock()
	defer t.con.m.Unlock()
	t.con.currentStream = nil
	if t.con.client != nil && t.stdin != nil {
		_ = t.stdin.Close()
	}
	t.con.client = nil

	if t.con.session != nil {
		traceLog.Info("[ssh]: session.Close()", "server", t.addr)
		_ = t.con.session.Close()
	}
	t.con.session = nil

	return nil
}

func (t *sshSmartSubtransport) Free() {
	traceLog.Info("[ssh]: sshSmartSubtransport.Free()")
	if t.con.client != nil {
		_ = t.con.client.Close()
	}

	if t.con.conn != nil {
		_ = t.con.conn.Close()
	}
	t.con.m.Lock()
	t.con.connected = false
	t.con.m.Unlock()
}

type sshSmartSubtransportStream struct {
	owner *sshSmartSubtransport
}

func (stream *sshSmartSubtransportStream) Read(buf []byte) (int, error) {
	return stream.owner.stdout.Read(buf)
}

func (stream *sshSmartSubtransportStream) Write(buf []byte) (int, error) {
	return stream.owner.stdin.Write(buf)
}

func (stream *sshSmartSubtransportStream) Free() {
	traceLog.Info("[ssh]: sshSmartSubtransportStream.Free()")
}

func createClientConfig(authOpts *git.AuthOptions) (*ssh.ClientConfig, error) {
	if authOpts == nil {
		return nil, fmt.Errorf("cannot create ssh client config from nil ssh auth options")
	}

	var signer ssh.Signer
	var err error
	if authOpts.Password != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(authOpts.Identity, []byte(authOpts.Password))
	} else {
		signer, err = ssh.ParsePrivateKey(authOpts.Identity)
	}
	if err != nil {
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:    authOpts.Username,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		Timeout: sshConnectionTimeOut,
	}

	if len(git.KexAlgos) > 0 {
		cfg.Config.KeyExchanges = git.KexAlgos
	}
	if len(git.HostKeyAlgos) > 0 {
		cfg.HostKeyAlgorithms = git.HostKeyAlgos
	}

	return cfg, nil
}
