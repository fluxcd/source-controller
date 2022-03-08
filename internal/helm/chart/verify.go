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
func VerifyProvenanceFile(keyring io.Reader, chartPath, provFilePath string) error {
	switch fi, err := os.Stat(chartPath); {
	case err != nil:
		return err
	case fi.IsDir():
		return fmt.Errorf("unpacked charts cannot be verified")
	case !isTar(chartPath):
		return fmt.Errorf("chart must be a tgz file")
	}

	if provFilePath == "" {
		provFilePath = chartPath + ".prov"
	}

	if _, err := os.Stat(provFilePath); err != nil {
		return fmt.Errorf("could not load provenance file %s: %w", provFilePath, err)
	}

	ring, err := openpgp.ReadKeyRing(keyring)
	if err != nil {
		return err
	}

	sig := &provenance.Signatory{KeyRing: ring}
	_, err = sig.Verify(chartPath, provFilePath)
	if err != nil {
		return err
	}
	return nil
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
