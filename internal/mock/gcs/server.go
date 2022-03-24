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

package gcs

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"

	raw "google.golang.org/api/storage/v1"
)

var (
	ObjectNotFound = errors.New("object not found")
)

// Object is a mock Server object.
type Object struct {
	Key            string
	Generation     int64
	MetaGeneration int64
	ContentType    string
	Content        []byte
}

// Server is a simple Google Cloud Storage mock server.
// It serves the provided Objects for the BucketName on the HTTPAddress when
// Start or StartTLS is called.
// It provides primitive support "Generation Conditions" when Object contents
// are fetched.
// Ref: https://pkg.go.dev/cloud.google.com/go/storage#hdr-Conditions
type Server struct {
	srv *httptest.Server
	mux *http.ServeMux

	BucketName string
	Objects    []*Object
}

func NewServer(bucketName string) *Server {
	s := &Server{BucketName: bucketName}
	s.mux = http.NewServeMux()
	s.mux.Handle("/", http.HandlerFunc(s.handler))

	s.srv = httptest.NewUnstartedServer(s.mux)

	return s
}

func (s *Server) Start() {
	s.srv.Start()
}

func (s *Server) StartTLS(config *tls.Config) {
	s.srv.TLS = config
	s.srv.StartTLS()
}

func (s *Server) Stop() {
	s.srv.Close()
}

func (s *Server) HTTPAddress() string {
	return s.srv.URL
}

func (s *Server) getAllObjects() *raw.Objects {
	objs := &raw.Objects{}
	for _, o := range s.Objects {
		objs.Items = append(objs.Items, getGCSObject(s.BucketName, *o))
	}
	return objs
}

func (s *Server) getObjectFile(key string, generation int64) ([]byte, error) {
	for _, o := range s.Objects {
		if o.Key == key {
			if generation == 0 || generation == o.Generation {
				return o.Content, nil
			}
		}
	}
	return nil, ObjectNotFound
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	uri := strings.TrimPrefix(r.RequestURI, "/storage/v1")

	switch {
	// Handle Bucket metadata related queries
	case strings.HasPrefix(uri, "/b/"):
		switch {
		// Return metadata about the Bucket
		case uri == fmt.Sprintf("/b/%s?alt=json&prettyPrint=false&projection=full", s.BucketName):
			etag := md5.New()
			for _, v := range s.Objects {
				etag.Write(v.Content)
			}
			response := getGCSBucket(s.BucketName, fmt.Sprintf("%x", etag.Sum(nil)))
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(200)
			w.Write(jsonResponse)
			return
		// Return metadata about a Bucket object
		case strings.Contains(uri, "/o/"):
			var obj *Object
			for _, o := range s.Objects {
				// The object key in the URI is escaped.
				// e.g.: /b/dummy/o/included%2Ffile.txt?alt=json&prettyPrint=false&projection=full
				if uri == fmt.Sprintf("/b/%s/o/%s?alt=json&prettyPrint=false&projection=full", s.BucketName, url.QueryEscape(o.Key)) {
					obj = o
					break
				}
			}
			if obj != nil {
				response := getGCSObject(s.BucketName, *obj)
				jsonResponse, err := json.Marshal(response)
				if err != nil {
					w.WriteHeader(500)
					return
				}
				w.WriteHeader(200)
				w.Write(jsonResponse)
				return
			}
			w.WriteHeader(404)
			return
		// Return metadata about all objects in the Bucket
		case strings.Contains(uri, "/o?"):
			response := s.getAllObjects()
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(200)
			w.Write(jsonResponse)
			return
		default:
			w.WriteHeader(404)
			return
		}
	// Handle object file query
	default:
		bucketPrefix := fmt.Sprintf("/%s/", s.BucketName)
		if strings.HasPrefix(uri, bucketPrefix) {
			// The URL path is of the format /<bucket>/included/file.txt.
			// Extract the object key by discarding the bucket prefix.
			key := strings.TrimPrefix(r.URL.Path, bucketPrefix)

			// Support "Generation Conditions"
			// https://pkg.go.dev/cloud.google.com/go/storage#hdr-Conditions
			var generation int64
			if matchGeneration := r.URL.Query().Get("ifGenerationMatch"); matchGeneration != "" {
				var err error
				if generation, err = strconv.ParseInt(matchGeneration, 10, 64); err != nil {
					w.WriteHeader(500)
					return
				}
			}

			// Handle returning object file in a bucket.
			response, err := s.getObjectFile(key, generation)
			if err != nil {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(200)
			w.Write(response)
			return
		}
		w.WriteHeader(404)
		return
	}
}

func getGCSObject(bucket string, obj Object) *raw.Object {
	hash := md5.Sum(obj.Content)
	etag := fmt.Sprintf("%x", hash)
	return &raw.Object{
		Bucket:         bucket,
		Name:           obj.Key,
		ContentType:    obj.ContentType,
		Generation:     obj.Generation,
		Metageneration: obj.MetaGeneration,
		Md5Hash:        etag,
		Etag:           etag,
	}
}

func getGCSBucket(name, eTag string) *raw.Bucket {
	return &raw.Bucket{
		Name:     name,
		Location: "loc",
		Etag:     eTag,
	}
}
