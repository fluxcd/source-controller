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
	"fmt"
	"net/url"
	"regexp"
)

type SanitizedError struct {
	err string
}

func (e SanitizedError) Error() string {
	return e.err
}

// SanitizeError extracts all URLs from the error message
// and replaces them with the URL without the query string.
func SanitizeError(err error) SanitizedError {
	errorMessage := err.Error()
	for _, u := range extractURLs(errorMessage) {
		urlWithoutQueryString, err := removeQueryString(u)
		if err == nil {
			re, err := regexp.Compile(fmt.Sprintf("%s*", regexp.QuoteMeta(u)))
			if err == nil {
				errorMessage = re.ReplaceAllString(errorMessage, urlWithoutQueryString)
			}
		}
	}

	return SanitizedError{errorMessage}
}

// removeQueryString takes a URL string as input and returns the URL without the query string.
func removeQueryString(urlStr string) (string, error) {
	// Parse the URL.
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	// Rebuild the URL without the query string.
	u.RawQuery = ""
	return u.String(), nil
}

// extractURLs takes a log message as input and returns the URLs found.
func extractURLs(logMessage string) []string {
	// Define a regular expression to match a URL.
	// This is a simple pattern and might need to be adjusted depending on the log message format.
	urlRegex := regexp.MustCompile(`https?://[^\s]+`)

	// Find the first match in the log message.
	matches := urlRegex.FindAllString(logMessage, -1)
	if len(matches) == 0 {
		return []string{}
	}

	return matches
}
