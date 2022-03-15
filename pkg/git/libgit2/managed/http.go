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
https://github.com/libgit2/git2go/blob/eae00773cce87d5282a8ac7c10b5c1961ee6f9cb/http.go

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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	git2go "github.com/libgit2/git2go/v33"
)

// registerManagedHTTP registers a Go-native implementation of an
// HTTP(S) transport that doesn't rely on any lower-level libraries
// such as OpenSSL.
func registerManagedHTTP() error {
	for _, protocol := range []string{"http", "https"} {
		_, err := git2go.NewRegisteredSmartTransport(protocol, true, httpSmartSubtransportFactory)
		if err != nil {
			return fmt.Errorf("failed to register transport for %q: %v", protocol, err)
		}
	}
	return nil
}

func httpSmartSubtransportFactory(remote *git2go.Remote, transport *git2go.Transport) (git2go.SmartSubtransport, error) {
	sst := &httpSmartSubtransport{
		transport: transport,
	}

	return sst, nil
}

type httpSmartSubtransport struct {
	transport *git2go.Transport
}

func (t *httpSmartSubtransport) Action(targetUrl string, action git2go.SmartServiceAction) (git2go.SmartSubtransportStream, error) {
	var proxyFn func(*http.Request) (*url.URL, error)
	proxyOpts, err := t.transport.SmartProxyOptions()
	if err != nil {
		return nil, err
	}
	switch proxyOpts.Type {
	case git2go.ProxyTypeNone:
		proxyFn = nil
	case git2go.ProxyTypeAuto:
		proxyFn = http.ProxyFromEnvironment
	case git2go.ProxyTypeSpecified:
		parsedUrl, err := url.Parse(proxyOpts.Url)
		if err != nil {
			return nil, err
		}

		proxyFn = http.ProxyURL(parsedUrl)
	}

	httpTransport := &http.Transport{
		// Add the proxy to the http transport.
		Proxy: proxyFn,

		// Set reasonable timeouts to ensure connections are not
		// left open in an idle state, nor they hang indefinitely.
		//
		// These are based on the official go http.DefaultTransport:
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client, req, err := createClientRequest(targetUrl, action, httpTransport)
	if err != nil {
		return nil, err
	}

	stream := newManagedHttpStream(t, req, client)
	if req.Method == "POST" {
		stream.recvReply.Add(1)
		stream.sendRequestBackground()
	}

	return stream, nil
}

func createClientRequest(targetUrl string, action git2go.SmartServiceAction, t *http.Transport) (*http.Client, *http.Request, error) {
	var req *http.Request
	var err error

	if t == nil {
		return nil, nil, fmt.Errorf("failed to create client: transport cannot be nil")
	}

	finalUrl := targetUrl
	opts, found := transportOptions(targetUrl)
	if found {
		if opts.TargetURL != "" {
			// override target URL only if options are found and a new targetURL
			// is provided.
			finalUrl = opts.TargetURL
		}

		// Add any provided certificate to the http transport.
		if len(opts.CABundle) > 0 {
			cap := x509.NewCertPool()
			if ok := cap.AppendCertsFromPEM(opts.CABundle); !ok {
				return nil, nil, fmt.Errorf("failed to use certificate from PEM")
			}
			t.TLSClientConfig = &tls.Config{
				RootCAs: cap,
			}
		}
	}

	client := &http.Client{Transport: t, Timeout: fullHttpClientTimeOut}

	switch action {
	case git2go.SmartServiceActionUploadpackLs:
		req, err = http.NewRequest("GET", finalUrl+"/info/refs?service=git-upload-pack", nil)

	case git2go.SmartServiceActionUploadpack:
		req, err = http.NewRequest("POST", finalUrl+"/git-upload-pack", nil)
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")

	case git2go.SmartServiceActionReceivepackLs:
		req, err = http.NewRequest("GET", finalUrl+"/info/refs?service=git-receive-pack", nil)

	case git2go.SmartServiceActionReceivepack:
		req, err = http.NewRequest("POST", finalUrl+"/git-receive-pack", nil)
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/x-git-receive-pack-request")

	default:
		err = errors.New("unknown action")
	}

	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", "git/2.0 (flux-libgit2)")
	return client, req, nil
}

func (t *httpSmartSubtransport) Close() error {
	return nil
}

func (t *httpSmartSubtransport) Free() {
}

type httpSmartSubtransportStream struct {
	owner       *httpSmartSubtransport
	client      *http.Client
	req         *http.Request
	resp        *http.Response
	reader      *io.PipeReader
	writer      *io.PipeWriter
	sentRequest bool
	recvReply   sync.WaitGroup
	httpError   error
	m           sync.RWMutex
}

func newManagedHttpStream(owner *httpSmartSubtransport, req *http.Request, client *http.Client) *httpSmartSubtransportStream {
	r, w := io.Pipe()
	return &httpSmartSubtransportStream{
		owner:  owner,
		client: client,
		req:    req,
		reader: r,
		writer: w,
	}
}

func (self *httpSmartSubtransportStream) Read(buf []byte) (int, error) {
	if !self.sentRequest {
		self.recvReply.Add(1)
		if err := self.sendRequest(); err != nil {
			return 0, err
		}
	}

	if err := self.writer.Close(); err != nil {
		return 0, err
	}

	self.recvReply.Wait()

	self.m.RLock()
	defer self.m.RUnlock()
	if self.httpError != nil {
		return 0, self.httpError
	}

	return self.resp.Body.Read(buf)
}

func (self *httpSmartSubtransportStream) Write(buf []byte) (int, error) {
	self.m.RLock()
	defer self.m.RUnlock()
	if self.httpError != nil {
		return 0, self.httpError
	}
	return self.writer.Write(buf)
}

func (self *httpSmartSubtransportStream) Free() {
	if self.resp != nil {
		self.resp.Body.Close()
	}
}

func (self *httpSmartSubtransportStream) sendRequestBackground() {
	go func() {
		err := self.sendRequest()

		self.m.Lock()
		self.httpError = err
		self.m.Unlock()
	}()
	self.sentRequest = true
}

func (self *httpSmartSubtransportStream) sendRequest() error {
	defer self.recvReply.Done()
	self.resp = nil

	var resp *http.Response
	var err error
	var userName string
	var password string

	// Obtain the credentials and use them if available.
	cred, err := self.owner.transport.SmartCredentials("", git2go.CredentialTypeUserpassPlaintext)
	if err != nil {
		// Passthrough error indicates that no credentials were provided.
		// Continue without credentials.
		if err.Error() != git2go.ErrorCodePassthrough.String() {
			return err
		}
	}

	if cred != nil {
		defer cred.Free()

		userName, password, err = cred.GetUserpassPlaintext()
		if err != nil {
			return err
		}
	}

	req := &http.Request{
		Method: self.req.Method,
		URL:    self.req.URL,
		Header: self.req.Header,
	}
	if req.Method == "POST" {
		req.Body = self.reader
		req.ContentLength = -1
	}

	req.SetBasicAuth(userName, password)
	resp, err = self.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		self.resp = resp
		self.sentRequest = true
		return nil
	}

	io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()
	return fmt.Errorf("Unhandled HTTP error %s", resp.Status)
}
