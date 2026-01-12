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
	"fmt"
	"io"
	"net/http"

	"helm.sh/helm/v4/pkg/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/fluxcd/pkg/oci"
)

var (
	// userAgent is the User-Agent header value sent with each request to an OCI registry
	// through the Helm/ORAS client. It extends the pkg/oci.UserAgent ("flux/v2") following
	// its format "<tool>/<version>".
	userAgent = fmt.Sprintf("%s/helm/v4/oras/v2", oci.UserAgent)
)

// NewClient creates a new OCI registry client with the provided options.
func NewClient(creds auth.CredentialFunc, tlsConfig *tls.Config, insecureHTTP bool) (*registry.Client, error) {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		baseTransport.TLSClientConfig = tlsConfig
	}
	client := auth.Client{
		Client: &http.Client{
			// We use the oras retry transport here to keep consistent with oras behavior.
			Transport: retry.NewTransport(baseTransport),
		},
		Header: http.Header{
			"User-Agent": {userAgent},
		},
		Credential: creds,
	}
	opts := []registry.ClientOption{
		registry.ClientOptWriter(io.Discard),
		registry.ClientOptAuthorizer(client),
	}
	if insecureHTTP {
		opts = append(opts, registry.ClientOptPlainHTTP())
	}
	return registry.NewClient(opts...)
}
