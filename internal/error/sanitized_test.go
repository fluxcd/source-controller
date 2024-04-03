/*
Copyright 2024 The Flux authors

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

package error

import (
	"errors"
	"testing"

	. "github.com/onsi/gomega"
)

func Test_extractURLs(t *testing.T) {

	tests := []struct {
		name       string
		logMessage string
		wantUrls   []string
	}{
		{
			name:       "Log Contains single URL",
			logMessage: "Get \"https://blobstorage.blob.core.windows.net/container/index.yaml?se=2024-05-01T16%3A28%3A26Z&sig=Signature&sp=rl&sr=c&st=2024-02-01T16%3A28%3A26Z&sv=2022-11-02\": dial tcp 20.60.53.129:443: connect: connection refused",
			wantUrls:   []string{"https://blobstorage.blob.core.windows.net/container/index.yaml?se=2024-05-01T16%3A28%3A26Z&sig=Signature&sp=rl&sr=c&st=2024-02-01T16%3A28%3A26Z&sv=2022-11-02\":"},
		},
		{
			name:       "Log Contains multiple URL",
			logMessage: "Get \"https://blobstorage.blob.core.windows.net/container/index.yaml?abc=es  https://blobstorage1.blob.core.windows.net/container/index.yaml?abc=no : dial tcp 20.60.53.129:443: connect: connection refused",
			wantUrls: []string{
				"https://blobstorage.blob.core.windows.net/container/index.yaml?abc=es",
				"https://blobstorage1.blob.core.windows.net/container/index.yaml?abc=no",
			},
		},
		{
			name:       "Log Contains No URL",
			logMessage: "Log message without URL",
			wantUrls:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			urls := extractURLs(tt.logMessage)

			g.Expect(len(urls)).To(Equal(len(tt.wantUrls)))
			for i := range tt.wantUrls {
				g.Expect(urls[i]).To(Equal(tt.wantUrls[i]))
			}
		})
	}
}

func Test_removeQueryString(t *testing.T) {

	tests := []struct {
		name    string
		urlStr  string
		wantUrl string
	}{
		{
			name:    "URL with query string",
			urlStr:  "https://blobstorage.blob.core.windows.net/container/index.yaml?se=2024-05-01T16%3A28%3A26Z&sig=Signature&sp=rl&sr=c&st=2024-02-01T16%3A28%3A26Z&sv=2022-11-02",
			wantUrl: "https://blobstorage.blob.core.windows.net/container/index.yaml",
		},
		{
			name:    "URL without query string",
			urlStr:  "https://blobstorage.blob.core.windows.net/container/index.yaml",
			wantUrl: "https://blobstorage.blob.core.windows.net/container/index.yaml",
		},
		{
			name:    "URL with query string and port",
			urlStr:  "https://blobstorage.blob.core.windows.net:443/container/index.yaml?se=2024-05-01T16%3A28%3A26Z&sig=Signature&sp=rl&sr=c&st=2024-02-01T16%3A28%3A26Z&sv=2022-11-02",
			wantUrl: "https://blobstorage.blob.core.windows.net:443/container/index.yaml",
		},
		{
			name:    "Invalid URL",
			urlStr:  "NoUrl",
			wantUrl: "NoUrl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			urlWithoutQueryString, err := removeQueryString(tt.urlStr)

			g.Expect(err).To(BeNil())
			g.Expect(urlWithoutQueryString).To(Equal(tt.wantUrl))
		})
	}
}

func Test_SanitizeError(t *testing.T) {

	tests := []struct {
		name           string
		errMessage     string
		wantErrMessage string
	}{
		{
			name:           "Log message with URL with query string",
			errMessage:     "Get \"https://blobstorage.blob.core.windows.net/container/index.yaml?se=2024-05-01T16%3A28%3A26Z&sig=Signature&sp=rl&sr=c&st=2024-02-01T16%3A28%3A26Z&sv=2022-11-02\": dial tcp 20.60.53.129:443: connect: connection refused",
			wantErrMessage: "Get \"https://blobstorage.blob.core.windows.net/container/index.yaml dial tcp 20.60.53.129:443: connect: connection refused",
		},
		{
			name:           "Log message without URL",
			errMessage:     "Log message contains no URL",
			wantErrMessage: "Log message contains no URL",
		},

		{
			name:           "Log message with multiple Urls",
			errMessage:     "Get \"https://blobstorage.blob.core.windows.net/container/index.yaml?abc=es  https://blobstorage1.blob.core.windows.net/container/index.yaml?abc=no dial tcp 20.60.53.129:443: connect: connection refused",
			wantErrMessage: "Get \"https://blobstorage.blob.core.windows.net/container/index.yaml  https://blobstorage1.blob.core.windows.net/container/index.yaml dial tcp 20.60.53.129:443: connect: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			err := SanitizeError(errors.New(tt.errMessage))
			g.Expect(err.Error()).To(Equal(tt.wantErrMessage))
		})
	}
}
