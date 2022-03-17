/*
Copyright 2021 The Flux authors

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

package chart

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
	"helm.sh/helm/v3/pkg/provenance"
)

// Ref: https://github.com/helm/helm/blob/v3.8.0/pkg/downloader/chart_downloader.go#L328
// modified to accept a custom provenance file path and an actual keyring instead of a
// path to the file containing the keyring.
func verifyChartWithProvFile(keyring io.Reader, chartPath, provFilePath string) (*provenance.Verification, error) {
	switch fi, err := os.Stat(chartPath); {
	case err != nil:
		return nil, err
	case fi.IsDir():
		return nil, fmt.Errorf("unpacked charts cannot be verified")
	case !isTar(chartPath):
		return nil, fmt.Errorf("chart must be a tgz file")
	}

	if provFilePath == "" {
		provFilePath = chartPath + ".prov"
	}

	if _, err := os.Stat(provFilePath); err != nil {
		return nil, fmt.Errorf("could not load provenance file %s: %w", provFilePath, err)
	}

	ring, err := openpgp.ReadKeyRing(keyring)
	if err != nil {
		return nil, err
	}

	sig := &provenance.Signatory{KeyRing: ring}
	verification, err := sig.Verify(chartPath, provFilePath)
	if err != nil {
		err = fmt.Errorf("failed to verify helm chart using provenance file: %w", err)
	}
	return verification, err
}

// isTar tests whether the given file is a tar file.
func isTar(filename string) bool {
	return strings.EqualFold(filepath.Ext(filename), ".tgz")
}

// Returns the path of a provenance file related to a packaged chart by
// adding ".prov" at the end, as per the Helm convention.
func provenanceFilePath(path string) string {
	return path + ".prov"
}

// ref: https://github.com/helm/helm/blob/v3.8.0/pkg/action/verify.go#L47-L51
type VerificationSignature struct {
	Identities     []string
	KeyFingerprint [20]byte
	FileHash       string
}

func buildVerificationSig(ver *provenance.Verification) *VerificationSignature {
	var verSig VerificationSignature
	if ver != nil {
		if ver.SignedBy != nil {
			for name := range ver.SignedBy.Identities {
				verSig.Identities = append(verSig.Identities, name)
			}
		}
		verSig.FileHash = ver.FileHash
		verSig.KeyFingerprint = ver.SignedBy.PrimaryKey.Fingerprint
	}
	return &verSig
}
