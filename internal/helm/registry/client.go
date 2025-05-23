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

package registry

import (
	"crypto/tls"
	"io"
	"net/http"

	"helm.sh/helm/v3/pkg/registry"
)

// ClientGenerator generates a registry client.
// The client is meant to be used for a single reconciliation.
func ClientGenerator(tlsConfig *tls.Config, isLogin, insecureHTTP bool) (*registry.Client, error) {
	if isLogin {
		rClient, err := newClient(tlsConfig, insecureHTTP)
		if err != nil {
			return nil, err
		}
		return rClient, nil
	}

	rClient, err := newClient(tlsConfig, insecureHTTP)
	if err != nil {
		return nil, err
	}
	return rClient, nil
}

func newClient(tlsConfig *tls.Config, insecureHTTP bool) (*registry.Client, error) {
	opts := []registry.ClientOption{
		registry.ClientOptWriter(io.Discard),
	}
	if insecureHTTP {
		opts = append(opts, registry.ClientOptPlainHTTP())
	}
	if tlsConfig != nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = tlsConfig
		opts = append(opts, registry.ClientOptHTTPClient(&http.Client{
			Transport: t,
		}))
	}
	return registry.NewClient(opts...)
}
