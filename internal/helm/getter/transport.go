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

package getter

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type TransportPool struct {
}

var pool = &sync.Pool{
	New: func() interface{} {
		return &http.Transport{
			DisableCompression: true,
			Proxy:              http.ProxyFromEnvironment,

			IdleConnTimeout: 60 * time.Second,

			// use safe defaults based off http.DefaultTransport
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	},
}

// NewOrIdle tries to return an existing transport that is not currently being used.
// If none is found, creates a new Transport instead.
//
// tlsConfig sets the TLSClientConfig for the transport and can be nil.
func NewOrIdle(tlsConfig *tls.Config) *http.Transport {
	t := pool.Get().(*http.Transport)
	t.TLSClientConfig = tlsConfig

	return t
}

// Release releases the transport back to the TransportPool after
// sanitising its sensitive fields.
func Release(transport *http.Transport) error {
	if transport == nil {
		return fmt.Errorf("cannot release nil transport")
	}

	transport.TLSClientConfig = nil

	pool.Put(transport)
	return nil
}
