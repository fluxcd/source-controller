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

package http

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	eTagHeaderName = "ETag"
)

var (
	// ErrorDirectoryExists is an error returned when the filename provided
	// is a directory.
	ErrorDirectoryExists = errors.New("filename is a directory")
)

// HttpClient is a minimal Google Cloud Storage client for fetching objects.
type HttpClient struct {
	// client for interacting with the Google Cloud
	// Storage APIs.
	baseURL *url.URL
	// Temporary directory to store the downloaded files
	baseTempPath string
	cached       bool
	eTag         string
}

// NewClient creates a new HTTP bucket client. The Client will automatically look for HTTP client
// credential.
func NewClient(ctx context.Context, baseURLString string, secret *corev1.Secret) (*HttpClient, error) {
	baseURL, err := url.Parse(baseURLString)
	if err != nil {
		return nil, err
	}
	tempPath, err := os.MkdirTemp("", "http-bucket-*")
	if err != nil {
		return nil, err
	}
	c := &HttpClient{
		baseURL:      baseURL,
		baseTempPath: tempPath,
	}
	if secret != nil {
		// TODO: add client certificate / HTTP auth support
	}
	return c, nil
}

// ValidateSecret validates the credential secret. The provided Secret may
// be nil.
func ValidateSecret(secret *corev1.Secret) error {
	if secret == nil {
		return nil
	}
	if _, exists := secret.Data["serviceaccount"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'serviceaccount'", secret.Name)
	}
	return nil
}

// BucketExists returns if an object storage bucket with the provided name
// exists, or returns a (client) error.
func (c *HttpClient) urlFor(bucketName string) string {
	baseURL := c.baseURL.String()
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return baseURL + bucketName
}

// BucketExists returns if an object storage bucket with the provided name
// exists, or returns a (client) error.
func (c *HttpClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	url := c.urlFor(bucketName)
	resp, err := http.Head(url)
	if err != nil {
		return false, err
	}

	defer func() {
		if err = resp.Body.Close(); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to close object reader")
		}
	}()

	return resp.StatusCode < 400, nil
}

// FGetObject gets the object from the provided object storage bucket, and
// writes it to targetPath.
// It returns the etag of the successfully fetched file, or any error.
func (c *HttpClient) FGetObject(ctx context.Context, bucketName, objectName, localPath string) (string, error) {
	// Verify if destination already exists.
	err := c.ensureDownload(ctx, bucketName)
	if err != nil {
		return "", err
	}

	dirStatus, err := os.Stat(localPath)
	if err == nil {
		// If the destination exists and is a directory.
		if dirStatus.IsDir() {
			return "", ErrorDirectoryExists
		}
	}

	// Proceed if file does not exist. return for all other errors.
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
	}

	// Extract top level directory.
	sourceFilePath := filepath.Join(c.baseTempPath, objectName)
	_, err = os.Stat(sourceFilePath)
	if err != nil {
		return "", err
	}

	objectDir, _ := filepath.Split(localPath)
	if objectDir != "" {
		// Create any missing top level directories.
		if err := os.MkdirAll(objectDir, 0o700); err != nil {
			return "", err
		}
	}

	// Prepare target file.
	objectFile, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}

	sourceFile, err := os.Open(sourceFilePath)
	defer func() {
		if err = sourceFile.Close(); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to close object reader")
		}
	}()

	// Write Object to file.
	if _, err := io.Copy(objectFile, sourceFile); err != nil {
		return "", err
	}

	_, err = sourceFile.Seek(0, io.SeekStart)
	if err != nil {
		return "", err
	}

	h, err := calculateHash(sourceFile)
	if err != nil {
		return "", err
	}

	// Close the file.
	if err := objectFile.Close(); err != nil {
		return "", err
	}

	return h, nil
}

// VisitObjects iterates over the items in the provided object storage
// bucket, calling visit for every item.
// If the underlying client or the visit callback returns an error,
// it returns early.
func (c *HttpClient) VisitObjects(ctx context.Context, bucketName string, visit func(path, etag string) error) error {
	err := c.ensureDownload(ctx, bucketName)
	if err != nil {
		return err
	}

	err = filepath.Walk(c.baseTempPath, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		err = visit(path[len(c.baseTempPath)+1:], "")
		return err
	})
	return err
}

func (c *HttpClient) ensureDownload(ctx context.Context, bucketName string) error {
	if c.cached {
		return nil
	}

	resp, err := http.Get(c.urlFor(bucketName))
	if err != nil {
		err = fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, err)
		return err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to close object reader")
		}
	}()

	f, err := os.CreateTemp("", bucketName+"*")
	if err != nil {
		return err
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to close temporary file")
		}
	}(f)

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		buf := make([]byte, 512)
		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		_, err = f.Read(buf)
		if err != nil {
			return err
		}

		contentType = http.DetectContentType(buf)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	switch contentType {
	case "application/zip":
		err = UnzipFile(f.Name(), c.baseTempPath)

	case "application/x-tar":
		err = UntarPackage(f.Name(), c.baseTempPath, false)

	case "application/gzip":
		err = UntarPackage(f.Name(), c.baseTempPath, true)

	default:
		var dest *os.File
		dest, err = os.OpenFile(filepath.Join(c.baseTempPath, bucketName), os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}

		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "failed to close temporary file")
			}
		}(dest)

		_, err = io.Copy(dest, f)
	}

	if err != nil {
		return err
	}

	c.eTag = resp.Header.Get(eTagHeaderName)
	if c.eTag == "" {
		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		etag, err := calculateHash(f)
		if err != nil {
			return err
		}

		c.eTag = etag
	}

	c.cached = true
	return nil
}

func calculateHash(reader io.Reader) (string, error) {
	sum := sha256.New()
	_, err := io.Copy(sum, reader)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

// Close closes the HTTP Client and logs any useful errors.
func (c *HttpClient) Close(ctx context.Context) {
	err := os.RemoveAll(c.baseTempPath)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to remove temporary directory: "+c.baseTempPath)
	}
}

// ObjectIsNotFound checks if the error provided is storage.ErrObjectNotExist.
func (c *HttpClient) ObjectIsNotFound(err error) bool {
	return os.IsNotExist(err)
}

// TODO: use fluxcd untar implementation
func UntarPackage(path string, dest string, gzipArchive bool) error {
	tarArchive, err := func() (io.ReadCloser, error) {
		archive, err := os.Open(path)
		if err != nil {
			//return nil, errors.New("unable to open archive file %s", path)
			return nil, err
		}

		if gzipArchive {
			gz, err := gzip.NewReader(archive)
			return gz, err
		}

		return archive, nil
	}()
	if err != nil {
		return err
	}

	defer func(tarArchive io.ReadCloser) {
		err := tarArchive.Close()
		if err != nil {

		}
	}(tarArchive)

	tarReader := tar.NewReader(tarArchive)
	for {
		hdr, err := tarReader.Next()
		switch {
		case err == io.EOF:
			return nil

		case err != nil:
			return err

		case hdr == nil:
			continue
		}

		dstEntryPath := filepath.Join(dest, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(dstEntryPath); err != nil {
				if !os.IsNotExist(err) {
					return err
				}

				if err := os.MkdirAll(dstEntryPath, 0755); err != nil {
					return err
				}
			}

		case tar.TypeReg:
			err = func() error {
				dir := filepath.Dir(dstEntryPath)
				err := os.MkdirAll(dir, 0755)
				if err != nil {
					return err
				}

				file, err := os.OpenFile(dstEntryPath, os.O_CREATE|os.O_RDWR, os.FileMode(hdr.Mode))
				if err != nil {
					return err
				}

				defer file.Close()

				_, err = io.Copy(file, tarReader)
				return err
			}()
			if err != nil && err != io.EOF {
				return err
				//return errors.Wrapf(err, "unable to extract %s", hdr.Name)
			}
		}
	}
}

// https://stackoverflow.com/questions/20357223/easy-way-to-unzip-file-with-golang
func UnzipFile(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			err := os.MkdirAll(path, f.Mode())
			if err != nil {
				return err
			}
		} else {
			err := os.MkdirAll(filepath.Dir(path), f.Mode())
			if err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}
