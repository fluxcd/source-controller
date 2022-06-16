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
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/go-logr/logr"
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
	var closed int32 = 0
	return &sshSmartSubtransport{
		transport:      transport,
		ctx:            context.Background(),
		logger:         logr.Discard(),
		closedSessions: &closed,
	}, nil
}

type sshSmartSubtransport struct {
	transport *git2go.Transport

	// once is used to ensure that logger and ctx is set only once,
	// on the initial (or only) Action call. Without this a mutex must
	// be applied to ensure that ctx won't be changed, as this would be
	// prone to race conditions in the stdout processing goroutine.
	once sync.Once
	// ctx defines the context to be used across long-running or
	// cancellable operations.
	// Defaults to context.Background().
	ctx context.Context
	// logger keeps a Logger instance for logging. This was preferred
	// due to the need to have a correlation ID and Address set and
	// reused across all log calls.
	// If context is not set, this defaults to logr.Discard().
	logger logr.Logger

	lastAction git2go.SmartServiceAction
	stdin      io.WriteCloser
	stdout     io.Reader

	closedSessions *int32

	client        *ssh.Client
	session       *ssh.Session
	currentStream *sshSmartSubtransportStream
	connected     bool
}

func (t *sshSmartSubtransport) Action(transportOptionsURL string, action git2go.SmartServiceAction) (git2go.SmartSubtransportStream, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	opts, found := getTransportOptions(transportOptionsURL)
	if !found {
		return nil, fmt.Errorf("could not find transport options for object: %s", transportOptionsURL)
	}

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
		if t.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionUploadpackLs {
				return t.currentStream, nil
			}
		}
		cmd = fmt.Sprintf("git-upload-pack '%s'", uPath)

	case git2go.SmartServiceActionReceivepackLs, git2go.SmartServiceActionReceivepack:
		if t.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionReceivepackLs {
				return t.currentStream, nil
			}
		}
		cmd = fmt.Sprintf("git-receive-pack '%s'", uPath)

	default:
		return nil, fmt.Errorf("unexpected action: %v", action)
	}

	port := "22"
	if u.Port() != "" {
		port = u.Port()
	}
	addr := net.JoinHostPort(u.Hostname(), port)

	t.once.Do(func() {
		if opts.Context != nil {
			t.ctx = opts.Context
			t.logger = ctrl.LoggerFrom(t.ctx,
				"transportType", "ssh",
				"addr", addr)
		}
	})

	sshConfig, err := createClientConfig(opts.AuthOpts)
	if err != nil {
		return nil, err
	}

	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		keyHash := sha256.Sum256(key.Marshal())
		return CheckKnownHost(hostname, opts.AuthOpts.KnownHosts, keyHash[:])
	}

	if t.connected {
		// The connection is no longer shared across actions, so ensures
		// all has been released before starting a new connection.
		_ = t.Close()
	}

	err = t.createConn(addr, sshConfig)
	if err != nil {
		return nil, err
	}

	t.logger.V(logger.TraceLevel).Info("creating new ssh session")
	if t.session, err = t.client.NewSession(); err != nil {
		return nil, err
	}

	if t.stdin, err = t.session.StdinPipe(); err != nil {
		return nil, err
	}

	var w *io.PipeWriter
	var reader io.Reader
	t.stdout, w = io.Pipe()
	if reader, err = t.session.StdoutPipe(); err != nil {
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
				t.logger.V(logger.TraceLevel).Error(errors.New(r.(string)),
					"recovered from libgit2 ssh smart subtransport panic")
			}
		}()
		var cancel context.CancelFunc
		ctx := t.ctx

		// When context is nil, creates a new with internal SSH connection timeout.
		if ctx == nil {
			ctx, cancel = context.WithTimeout(context.Background(), sshConnectionTimeOut)
			defer cancel()
		}

		closedAlready := atomic.LoadInt32(t.closedSessions)
		for {
			select {
			case <-ctx.Done():
				t.Close()
				return nil

			default:
				if atomic.LoadInt32(t.closedSessions) > closedAlready {
					return nil
				}

				_, err := io.Copy(w, reader)
				if err != nil {
					return err
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	t.logger.V(logger.TraceLevel).Info("run on remote", "cmd", cmd)
	if err := t.session.Start(cmd); err != nil {
		return nil, err
	}

	t.lastAction = action
	t.currentStream = &sshSmartSubtransportStream{
		owner: t,
	}

	return t.currentStream, nil
}

func (t *sshSmartSubtransport) createConn(addr string, sshConfig *ssh.ClientConfig) error {
	ctx, cancel := context.WithTimeout(context.TODO(), sshConnectionTimeOut)
	defer cancel()

	t.logger.V(logger.TraceLevel).Info("dial connection")
	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		return err
	}

	t.connected = true
	t.client = ssh.NewClient(c, chans, reqs)

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
	t.logger.V(logger.TraceLevel).Info("sshSmartSubtransport.Close()")

	t.currentStream = nil
	if t.client != nil && t.stdin != nil {
		_ = t.stdin.Close()
	}
	t.stdin = nil

	if t.session != nil {
		t.logger.V(logger.TraceLevel).Info("session.Close()")
		_ = t.session.Close()
	}
	t.session = nil

	if t.client != nil {
		_ = t.client.Close()
		t.logger.V(logger.TraceLevel).Info("close client")
	}
	t.client = nil

	t.connected = false
	atomic.AddInt32(t.closedSessions, 1)

	return nil
}

func (t *sshSmartSubtransport) Free() {
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
