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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	pool "github.com/fluxcd/source-controller/internal/transport"
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
	traceLog.Info("[http]: httpSmartSubtransportFactory")
	sst := &httpSmartSubtransport{
		transport:     transport,
		httpTransport: pool.NewOrIdle(nil),
	}

	return sst, nil
}

type httpSmartSubtransport struct {
	transport     *git2go.Transport
	httpTransport *http.Transport
}

func (t *httpSmartSubtransport) Action(transportAuthID string, action git2go.SmartServiceAction) (git2go.SmartSubtransportStream, error) {
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

	t.httpTransport.Proxy = proxyFn
	t.httpTransport.DisableCompression = false

	client, req, err := createClientRequest(transportAuthID, action, t.httpTransport)
	if err != nil {
		return nil, err
	}

	stream := newManagedHttpStream(t, req, client)
	if req.Method == "POST" {
		stream.recvReply.Add(1)
		stream.sendRequestBackground()
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}

		// golang will change POST to GET in case of redirects.
		if len(via) >= 0 && req.Method != via[0].Method {
			if via[0].URL.Scheme == "https" && req.URL.Scheme == "http" {
				return fmt.Errorf("downgrade from https to http is not allowed: from %q to %q", via[0].URL.String(), req.URL.String())
			}
			if via[0].URL.Host != req.URL.Host {
				return fmt.Errorf("cross hosts redirects are not allowed: from %s to %s", via[0].URL.Host, req.URL.Host)
			}

			return http.ErrUseLastResponse
		}
		return nil
	}

	return stream, nil
}

func createClientRequest(transportAuthID string, action git2go.SmartServiceAction, t *http.Transport) (*http.Client, *http.Request, error) {
	var req *http.Request
	var err error

	if t == nil {
		return nil, nil, fmt.Errorf("failed to create client: transport cannot be nil")
	}

	opts, found := getTransportOptions(transportAuthID)

	if !found {
		return nil, nil, fmt.Errorf("failed to create client: could not find transport options for the object: %s", transportAuthID)
	}
	targetURL := opts.TargetURL

	if len(targetURL) > URLMaxLength {
		return nil, nil, fmt.Errorf("URL exceeds the max length (%d)", URLMaxLength)
	}

	client := &http.Client{
		Transport: t,
		Timeout:   fullHttpClientTimeOut,
	}

	switch action {
	case git2go.SmartServiceActionUploadpackLs:
		req, err = http.NewRequest("GET", targetURL+"/info/refs?service=git-upload-pack", nil)

	case git2go.SmartServiceActionUploadpack:
		req, err = http.NewRequest("POST", targetURL+"/git-upload-pack", nil)
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")

	case git2go.SmartServiceActionReceivepackLs:
		req, err = http.NewRequest("GET", targetURL+"/info/refs?service=git-receive-pack", nil)

	case git2go.SmartServiceActionReceivepack:
		req, err = http.NewRequest("POST", targetURL+"/git-receive-pack", nil)
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

	// Add any provided certificate to the http transport.
	if opts.AuthOpts != nil {
		req.SetBasicAuth(opts.AuthOpts.Username, opts.AuthOpts.Password)
		if len(opts.AuthOpts.CAFile) > 0 {
			certPool := x509.NewCertPool()
			if ok := certPool.AppendCertsFromPEM(opts.AuthOpts.CAFile); !ok {
				return nil, nil, fmt.Errorf("failed to use certificate from PEM")
			}
			t.TLSClientConfig = &tls.Config{
				RootCAs: certPool,
			}
		}
	}

	req.Header.Set("User-Agent", "git/2.0 (flux-libgit2)")
	return client, req, nil
}

func (t *httpSmartSubtransport) Close() error {
	traceLog.Info("[http]: httpSmartSubtransport.Close()")
	return nil
}

func (t *httpSmartSubtransport) Free() {
	traceLog.Info("[http]: httpSmartSubtransport.Free()")

	if t.httpTransport != nil {
		traceLog.Info("[http]: release http transport back to pool")
		pool.Release(t.httpTransport)
		t.httpTransport = nil
	}
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
	err := self.httpError
	self.m.RUnlock()

	if err != nil {
		return 0, self.httpError
	}
	return self.resp.Body.Read(buf)
}

func (self *httpSmartSubtransportStream) Write(buf []byte) (int, error) {
	self.m.RLock()
	err := self.httpError
	self.m.RUnlock()

	if err != nil {
		return 0, self.httpError
	}
	return self.writer.Write(buf)
}

func (self *httpSmartSubtransportStream) Free() {
	if self.resp != nil {
		traceLog.Info("[http]: httpSmartSubtransportStream.Free()")

		if self.resp.Body != nil {
			// ensure body is fully processed and closed
			// for increased likelihood of transport reuse in HTTP/1.x.
			// it should not be a problem to do this more than once.
			if _, err := io.Copy(io.Discard, self.resp.Body); err != nil {
				traceLog.Error(err, "[http]: cannot discard response body")
			}

			if err := self.resp.Body.Close(); err != nil {
				traceLog.Error(err, "[http]: cannot close response body")
			}
		}
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
	var content []byte

	for {
		req := &http.Request{
			Method: self.req.Method,
			URL:    self.req.URL,
			Header: self.req.Header,
		}
		if req.Method == "POST" {
			if len(content) == 0 {
				// a copy of the request body needs to be saved so
				// it can be reused in case of redirects.
				if content, err = io.ReadAll(self.reader); err != nil {
					return err
				}
			}
			req.Body = io.NopCloser(bytes.NewReader(content))
			req.ContentLength = -1
		}

		traceLog.Info("[http]: new request", "method", req.Method, "URL", req.URL)
		resp, err = self.client.Do(req)
		if err != nil {
			return err
		}

		// GET requests will be automatically redirected.
		// POST require the new destination, and also the body content.
		if req.Method == "POST" && resp.StatusCode >= 301 && resp.StatusCode <= 308 {
			// ensure body is fully processed and closed
			// for increased likelihood of transport reuse in HTTP/1.x.
			_, _ = io.Copy(io.Discard, resp.Body) // errors can be safely ignored

			if err := resp.Body.Close(); err != nil {
				return err
			}

			// The next try will go against the new destination
			self.req.URL, err = resp.Location()
			if err != nil {
				return err
			}

			traceLog.Info("[http]: POST redirect", "URL", self.req.URL)
			continue
		}

		// for HTTP 200, the response will be cleared up by Free()
		if resp.StatusCode == http.StatusOK {
			break
		}

		// ensure body is fully processed and closed
		// for increased likelihood of transport reuse in HTTP/1.x.
		_, _ = io.Copy(io.Discard, resp.Body) // errors can be safely ignored
		if err := resp.Body.Close(); err != nil {
			return err
		}

		return fmt.Errorf("Unhandled HTTP error %s", resp.Status)
	}

	self.resp = resp
	self.sentRequest = true
	return nil
}
