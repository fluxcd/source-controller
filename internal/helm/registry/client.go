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
	"os"

	"helm.sh/helm/v3/pkg/registry"
	"k8s.io/apimachinery/pkg/util/errors"
)

// ClientGenerator generates a registry client and a temporary credential file.
// The client is meant to be used for a single reconciliation.
// The file is meant to be used for a single reconciliation and deleted after.
func ClientGenerator(tlsConfig *tls.Config, isLogin bool) (*registry.Client, string, error) {
	if isLogin {
		// create a temporary file to store the credentials
		// this is needed because otherwise the credentials are stored in ~/.docker/config.json.
		credentialsFile, err := os.CreateTemp("", "credentials")
		if err != nil {
			return nil, "", err
		}

		var errs []error
		rClient, err := newClient(credentialsFile.Name(), tlsConfig)
		if err != nil {
			errs = append(errs, err)
			// attempt to delete the temporary file
			if credentialsFile != nil {
				err := os.Remove(credentialsFile.Name())
				if err != nil {
					errs = append(errs, err)
				}
			}
			return nil, "", errors.NewAggregate(errs)
		}
		return rClient, credentialsFile.Name(), nil
	}

	rClient, err := newClient("", tlsConfig)
	if err != nil {
		return nil, "", err
	}
	return rClient, "", nil
}

func newClient(credentialsFile string, tlsConfig *tls.Config) (*registry.Client, error) {
	opts := []registry.ClientOption{
		registry.ClientOptWriter(io.Discard),
	}
	if tlsConfig != nil {
		opts = append(opts, registry.ClientOptHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}))
	}
	if credentialsFile != "" {
		opts = append(opts, registry.ClientOptCredentialsFile(credentialsFile))
	}

	return registry.NewClient(opts...)
}
