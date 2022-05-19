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

package util

import (
	"io"
	"os"

	"helm.sh/helm/v3/pkg/registry"
)

// RegistryClientGenerator generates a registry client and a temporary credential file.
// The client is meant to be used for a single reconciliation.
// The file is meant to be used for a single reconciliation and deleted after.
func RegistryClientGenerator(isLogin bool) (*registry.Client, string, error) {
	if isLogin {
		// create a temporary file to store the credentials
		// this is needed because otherwise the credentials are stored in ~/.docker/config.json.
		credentialFile, err := os.CreateTemp("", "credentials")
		if err != nil {
			return nil, "", err
		}

		rClient, err := registry.NewClient(registry.ClientOptWriter(io.Discard), registry.ClientOptCredentialsFile(credentialFile.Name()))
		if err != nil {
			return nil, "", err
		}
		return rClient, credentialFile.Name(), nil
	}

	rClient, err := registry.NewClient(registry.ClientOptWriter(io.Discard))
	if err != nil {
		return nil, "", err
	}
	return rClient, "", nil
}
