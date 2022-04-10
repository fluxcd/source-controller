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
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fluxcd/source-controller/pkg/git"
	git2go "github.com/libgit2/git2go/v33"
)

// registerManagedSSH registers a new Go-native protocol ssh+managed://.
// It implementation doesn't rely on any lower-level libraries such as libssh2.
// The built-in protocols that rely on libssh2 are kept intact,under protocols:
// "ssh://", "ssh+git://" and "git+ssh://".
//
// When using ssh+managed://, the underlying SSH connections are kept open and
//  are reused across several SSH sessions. This is due to upstream issues in
// which concurrent/parallel SSH connections may lead to instability.
//
// Connections are created on first attempt to use a given remote. The
// connection is removed from the cache at the first failed SSH session.
//
// https://github.com/golang/go/issues/51926
// https://github.com/golang/go/issues/27140
func registerManagedSSH() error {
	for _, protocol := range []string{SSHManagedProtocol} {
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

	lastAction    git2go.SmartServiceAction
	client        *ssh.Client
	session       *ssh.Session
	stdin         io.WriteCloser
	stdout        io.Reader
	currentStream *sshSmartSubtransportStream
	ckey          string
	addr          string
	singleUse     bool
}

// aMux is the read-write mutex to control access to sshClients.
var aMux sync.RWMutex

type cachedClient struct {
	*ssh.Client
	activeSessions uint16
}

// sshClients stores active ssh clients/connections to be reused.
//
// Once opened, connections will be kept cached until an error occurs
// during SSH commands, by which point it will be discarded, leading to
// a follow-up cache miss.
//
// The key must be based on cacheKey, refer to that function's comments.
var sshClients map[string]*cachedClient = make(map[string]*cachedClient)

func (t *sshSmartSubtransport) Action(urlString string, action git2go.SmartServiceAction) (git2go.SmartSubtransportStream, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	u, err := url.Parse(urlString)
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
			// Disregard errors from previous stream, futher details inside Close().
			_ = t.Close()
		}
		cmd = fmt.Sprintf("git-upload-pack '%s'", uPath)

	case git2go.SmartServiceActionReceivepackLs, git2go.SmartServiceActionReceivepack:
		if t.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionReceivepackLs {
				return t.currentStream, nil
			}
			// Disregard errors from previous stream, futher details inside Close().
			_ = t.Close()
		}
		cmd = fmt.Sprintf("git-receive-pack '%s'", uPath)

	default:
		return nil, fmt.Errorf("unexpected action: %v", action)
	}

	cred, err := t.transport.SmartCredentials("", git2go.CredentialTypeSSHMemory)
	if err != nil {
		return nil, err
	}
	defer cred.Free()

	var addr string
	port := "22"
	if u.Port() != "" {
		port = u.Port()
	}
	addr = fmt.Sprintf("%s:%s", u.Hostname(), port)
	t.addr = addr

	ckey, sshConfig, err := cacheKeyAndConfig(addr, cred)
	if err != nil {
		return nil, err
	}
	t.ckey = ckey

	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		marshaledKey := key.Marshal()
		cert := &git2go.Certificate{
			Kind: git2go.CertificateHostkey,
			Hostkey: git2go.HostkeyCertificate{
				Kind:         git2go.HostkeySHA1 | git2go.HostkeyMD5 | git2go.HostkeySHA256 | git2go.HostkeyRaw,
				HashMD5:      md5.Sum(marshaledKey),
				HashSHA1:     sha1.Sum(marshaledKey),
				HashSHA256:   sha256.Sum256(marshaledKey),
				Hostkey:      marshaledKey,
				SSHPublicKey: key,
			},
		}

		return t.transport.SmartCertificateCheck(cert, true, hostname)
	}

	var cacheHit bool
	aMux.Lock()
	if c, ok := sshClients[ckey]; ok {
		traceLog.Info("[ssh]: cache hit", "remoteAddress", addr)
		t.client = c.Client
		cacheHit = true
		c.activeSessions++
	}
	aMux.Unlock()

	if t.client == nil {
		cacheHit = false
		traceLog.Info("[ssh]: cache miss", "remoteAddress", addr)
		err := t.createConn(ckey, addr, sshConfig)
		if err != nil {
			return nil, err
		}
	}

	traceLog.Info("[ssh]: creating new ssh session")
	if t.session, err = t.client.NewSession(); err != nil {
		discardCachedSshClient(ckey)

		// if the current connection was cached, we can try again
		// as this may be a stale connection.
		if !cacheHit {
			return nil, err
		}

		traceLog.Info("[ssh]: cached connection was stale, retrying...")
		err = t.createConn(ckey, addr, sshConfig)
		if err != nil {
			return nil, err
		}

		traceLog.Info("[ssh]: creating new ssh session with new connection")
		t.session, err = t.client.NewSession()
		if err != nil {
			discardCachedSshClient(ckey)
			return nil, err
		}
	}

	if t.stdin, err = t.session.StdinPipe(); err != nil {
		discardCachedSshClient(ckey)
		return nil, err
	}

	if t.stdout, err = t.session.StdoutPipe(); err != nil {
		discardCachedSshClient(ckey)
		return nil, err
	}

	traceLog.Info("[ssh]: run on remote", "cmd", cmd)
	if err := t.session.Start(cmd); err != nil {
		discardCachedSshClient(ckey)
		return nil, err
	}

	t.lastAction = action
	t.currentStream = &sshSmartSubtransportStream{
		owner: t,
	}

	return t.currentStream, nil
}

func (t *sshSmartSubtransport) createConn(ckey, addr string, sshConfig *ssh.ClientConfig) error {
	// In some scenarios the ssh handshake can hang indefinitely at
	// golang.org/x/crypto/ssh.(*handshakeTransport).kexLoop.
	//
	// xref: https://github.com/golang/go/issues/51926
	done := make(chan error, 1)
	var err error

	var c *ssh.Client
	go func() {
		c, err = ssh.Dial("tcp", addr, sshConfig)
		done <- err
	}()

	dialTimeout := sshConfig.Timeout + (30 * time.Second)

	select {
	case doneErr := <-done:
		if doneErr != nil {
			err = fmt.Errorf("ssh.Dial: %w", doneErr)
		}
	case <-time.After(dialTimeout):
		err = fmt.Errorf("timed out waiting for ssh.Dial after %s", dialTimeout)
	}

	if err != nil {
		return err
	}

	t.client = c
	t.singleUse = !cacheableConnection(addr)

	if !t.singleUse {
		// Mutex is set here to avoid the network latency being
		// absorbed by all competing goroutines.
		aMux.Lock()
		defer aMux.Unlock()

		// A different goroutine won the race, dispose the connection
		// and carry on.
		if _, ok := sshClients[ckey]; ok {
			go func() {
				_ = c.Close()
			}()
			return nil
		}

		sshClients[ckey] = &cachedClient{
			Client:         c,
			activeSessions: 1,
		}
	}
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
	t.currentStream = nil
	if t.client != nil && t.stdin != nil {
		_ = t.stdin.Close()
	}
	t.client = nil

	if t.session != nil {
		traceLog.Info("[ssh]: session.Close()", "server", t.addr)
		_ = t.session.Close()
	}
	t.session = nil

	return nil
}

func (t *sshSmartSubtransport) Free() {
	traceLog.Info("[ssh]: sshSmartSubtransport.Free()")
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
	if stream.owner == nil {
		return
	}

	if stream.owner.ckey != "" {
		decrementActiveSessionIfFound(stream.owner.ckey)
	}

	if stream.owner.singleUse && stream.owner.client != nil {
		_ = stream.owner.client.Close()
	}
}

func cacheKeyAndConfig(remoteAddress string, cred *git2go.Credential) (string, *ssh.ClientConfig, error) {
	if cred == nil {
		return "", nil, fmt.Errorf("cannot create cache key from a nil credential")
	}

	username, _, privatekey, passphrase, err := cred.GetSSHKey()
	if err != nil {
		return "", nil, err
	}

	var pemBytes []byte
	if cred.Type() == git2go.CredentialTypeSSHMemory {
		pemBytes = []byte(privatekey)
	} else {
		return "", nil, fmt.Errorf("file based SSH credential is not supported")
	}

	// must include the passphrase, otherwise a caller that knows the private key, but
	// not its passphrase would be able to bypass auth.
	ck := cacheKey(remoteAddress, username, passphrase, pemBytes)

	var key ssh.Signer
	if passphrase != "" {
		key, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	} else {
		key, err = ssh.ParsePrivateKey(pemBytes)
	}

	if err != nil {
		return "", nil, err
	}

	cfg := &ssh.ClientConfig{
		User:    username,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(key)},
		Timeout: sshConnectionTimeOut,
	}
	if len(git.KexAlgos) > 0 {
		cfg.Config.KeyExchanges = git.KexAlgos
	}

	return ck, cfg, nil
}

// cacheKey generates a cache key that is multi-tenancy safe.
//
// Stablishing multiple and concurrent ssh connections leads to stability
// issues documented above. However, the caching/sharing of already stablished
// connections could represent a vector for users to bypass the ssh authentication
// mechanism.
//
// cacheKey tries to ensure that connections are only shared by users that
// have the exact same remoteAddress and credentials.
func cacheKey(remoteAddress, userName, passphrase string, pubKey []byte) string {
	h := sha256.New()

	v := fmt.Sprintf("%s-%s-%s-%v", remoteAddress, userName, passphrase, pubKey)

	h.Write([]byte(v))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// discardCachedSshClient discards the cached ssh client, forcing the next git operation
// to create a new one via ssh.Dial.
func discardCachedSshClient(key string) {
	aMux.Lock()
	defer aMux.Unlock()

	if v, found := sshClients[key]; found {
		traceLog.Info("[ssh]: discard cached ssh client", "activeSessions", v.activeSessions)
		closeConn := func() {
			// run as async goroutine to minimise mutex time in immediate closures.
			go func() {
				if v.Client != nil {
					_ = v.Client.Close()
				}
			}()
		}

		// if no active sessions for this connection, close it right-away.
		// otherwise, it may be used by other processes, so remove from cache,
		// and schedule a delayed closure.
		if v.activeSessions == 0 {
			traceLog.Info("[ssh]: closing connection")
			closeConn()
		} else {
			go func() {
				// the delay must account for in-flight operations
				// that depends on this connection.
				time.Sleep(120 * time.Second)
				traceLog.Info("[ssh]: closing connection after delay")
				closeConn()
			}()
		}
		delete(sshClients, key)
	}
}

func decrementActiveSessionIfFound(key string) {
	aMux.Lock()
	defer aMux.Unlock()

	if v, found := sshClients[key]; found {
		v.activeSessions--
	}
}

func cacheableConnection(addr string) bool {
	return !Contains(denyConcurrentConnections, addr)
}
