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

	"golang.org/x/crypto/ssh"

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

	lastAction    git2go.SmartServiceAction
	client        *ssh.Client
	session       *ssh.Session
	stdin         io.WriteCloser
	stdout        io.Reader
	currentStream *sshSmartSubtransportStream
}

func (t *sshSmartSubtransport) Action(urlString string, action git2go.SmartServiceAction) (git2go.SmartSubtransportStream, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	u, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}

	// Escape \ and '.
	uPath := strings.Replace(u.Path, `\`, `\\`, -1)
	uPath = strings.Replace(uPath, `'`, `\'`, -1)

	// TODO: Add percentage decode similar to libgit2.
	// Refer: https://github.com/libgit2/libgit2/blob/358a60e1b46000ea99ef10b4dd709e92f75ff74b/src/str.c#L455-L481

	var cmd string
	switch action {
	case git2go.SmartServiceActionUploadpackLs, git2go.SmartServiceActionUploadpack:
		if t.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionUploadpackLs {
				return t.currentStream, nil
			}
			t.Close()
		}
		cmd = fmt.Sprintf("git-upload-pack '%s'", uPath)

	case git2go.SmartServiceActionReceivepackLs, git2go.SmartServiceActionReceivepack:
		if t.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionReceivepackLs {
				return t.currentStream, nil
			}
			t.Close()
		}
		cmd = fmt.Sprintf("git-receive-pack '%s'", uPath)

	default:
		return nil, fmt.Errorf("unexpected action: %v", action)
	}

	cred, err := t.transport.SmartCredentials("", git2go.CredentialTypeSSHKey|git2go.CredentialTypeSSHMemory)
	if err != nil {
		return nil, err
	}
	defer cred.Free()

	sshConfig, err := getSSHConfigFromCredential(cred)
	if err != nil {
		return nil, err
	}
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

	var addr string
	if u.Port() != "" {
		addr = fmt.Sprintf("%s:%s", u.Hostname(), u.Port())
	} else {
		addr = fmt.Sprintf("%s:22", u.Hostname())
	}

	// In some scenarios the ssh handshake can hang indefinitely at
	// golang.org/x/crypto/ssh.(*handshakeTransport).kexLoop.
	//
	// xref: https://github.com/golang/go/issues/51926
	done := make(chan error, 1)
	go func() {
		t.client, err = ssh.Dial("tcp", addr, sshConfig)
		done <- err
	}()

	select {
	case doneErr := <-done:
		if doneErr != nil {
			err = fmt.Errorf("ssh.Dial: %w", doneErr)
		}
	case <-time.After(sshConfig.Timeout + (5 * time.Second)):
		err = fmt.Errorf("timed out waiting for ssh.Dial")
	}

	if err != nil {
		return nil, err
	}

	t.session, err = t.client.NewSession()
	if err != nil {
		return nil, err
	}

	t.stdin, err = t.session.StdinPipe()
	if err != nil {
		return nil, err
	}

	t.stdout, err = t.session.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := t.session.Start(cmd); err != nil {
		return nil, err
	}

	t.lastAction = action
	t.currentStream = &sshSmartSubtransportStream{
		owner: t,
	}

	return t.currentStream, nil
}

func (t *sshSmartSubtransport) Close() error {
	t.currentStream = nil
	if t.client != nil {
		t.stdin.Close()
		t.session.Wait()
		t.session.Close()
		t.client = nil
	}
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

func getSSHConfigFromCredential(cred *git2go.Credential) (*ssh.ClientConfig, error) {
	username, _, privatekey, passphrase, err := cred.GetSSHKey()
	if err != nil {
		return nil, err
	}

	var pemBytes []byte
	if cred.Type() == git2go.CredentialTypeSSHMemory {
		pemBytes = []byte(privatekey)
	} else {
		return nil, fmt.Errorf("file based SSH credential is not supported")
	}

	var key ssh.Signer
	if passphrase != "" {
		key, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	} else {
		key, err = ssh.ParsePrivateKey(pemBytes)
	}

	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:    username,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(key)},
		Timeout: sshConnectionTimeOut,
	}, nil
}
