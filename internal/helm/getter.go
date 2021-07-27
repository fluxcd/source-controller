/*
Copyright 2020 The Flux authors

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

package helm

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
)

// ClientOptionsFromSecret constructs a getter.Option slice for the given secret,
// storing any temporary credentials .
// It returns the slice, and a callback to remove temporary files.
func ClientOptionsFromSecret(secret corev1.Secret, dir string) ([]getter.Option, error) {
	var opts []getter.Option
	basicAuth, err := BasicAuthFromSecret(secret)
	if err != nil {
		return opts, err
	}
	if basicAuth != nil {
		opts = append(opts, basicAuth)
	}
	tlsClientConfig, err := TLSClientConfigFromSecret(secret, dir)
	if err != nil {
		return opts, err
	}
	if tlsClientConfig != nil {
		opts = append(opts, tlsClientConfig)
	}
	return opts, nil
}

// BasicAuthFromSecret attempts to construct a basic auth getter.Option for the
// given v1.Secret and returns the result.
//
// Secrets with no username AND password are ignored, if only one is defined it
// returns an error.
func BasicAuthFromSecret(secret corev1.Secret) (getter.Option, error) {
	username, password := string(secret.Data["username"]), string(secret.Data["password"])
	switch {
	case username == "" && password == "":
		return nil, nil
	case username == "" || password == "":
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'username' and 'password'", secret.Name)
	}
	return getter.WithBasicAuth(username, password), nil
}

// TLSClientConfigFromSecret attempts to construct a TLS client config
// getter.Option for the given v1.Secret. It returns the getter.Option and a
// callback to remove the temporary TLS files.
//
// Secrets with no certFile, keyFile, AND caFile are ignored, if only a
// certBytes OR keyBytes is defined it returns an error.
func TLSClientConfigFromSecret(secret corev1.Secret, dir string) (getter.Option, error) {
	certBytes, keyBytes, caBytes := secret.Data["certFile"], secret.Data["keyFile"], secret.Data["caFile"]
	switch {
	case len(certBytes)+len(keyBytes)+len(caBytes) == 0:
		return nil, nil
	case (len(certBytes) > 0 && len(keyBytes) == 0) || (len(keyBytes) > 0 && len(certBytes) == 0):
		return nil, fmt.Errorf("invalid '%s' secret data: fields 'certFile' and 'keyFile' require each other's presence",
			secret.Name)
	}

	var certFile, keyFile, caFile string
	if len(certBytes) > 0 && len(keyBytes) > 0 {
		f, err := os.CreateTemp(dir, "cert-")
		if err != nil {

		}
		if _, err = io.Copy(f, bytes.NewReader(certBytes)); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		certFile = f.Name()

		f, err = os.CreateTemp(dir, "key-")
		if err != nil {
			f.Close()
			return nil, err
		}
		if _, err = io.Copy(f, bytes.NewReader(keyBytes)); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		keyFile = f.Name()
	}

	if len(caBytes) > 0 {
		f, err := os.CreateTemp(dir, "ca-")
		if err != nil {
			f.Close()
			return nil, err
		}
		if _, err = io.Copy(f, bytes.NewReader(caBytes)); err != nil {
			f.Close()
		}
		f.Close()
		caFile = f.Name()
	}

	return getter.WithTLSClientConfig(certFile, keyFile, caFile), nil
}
