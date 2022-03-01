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

package s3

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Object is a mock Server object.
type Object struct {
	Key          string
	LastModified time.Time
	ContentType  string
	Content      []byte
}

// Server is a simple AWS S3 mock server.
// It serves the provided Objects for the BucketName on the HTTPAddress when
// Start or StartTLS is called.
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

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	key := path.Base(r.URL.Path)

	switch key {
	case s.BucketName:
		w.Header().Add("Content-Type", "application/xml")

		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}

		if r.URL.Query().Has("location") {
			w.WriteHeader(200)
			w.Write([]byte(`
<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">Europe</LocationConstraint>
			`))
			return
		}

		contents := ""
		for _, o := range s.Objects {
			etag := md5.Sum(o.Content)
			contents += fmt.Sprintf(`
		<Contents>
			<Key>%s</Key>
			<LastModified>%s</LastModified>
			<Size>%d</Size>
			<ETag>&quot;%x&quot;</ETag>
			<StorageClass>STANDARD</StorageClass>
		</Contents>`, o.Key, o.LastModified.UTC().Format(time.RFC3339), len(o.Content), etag)
		}

		fmt.Fprintf(w, `
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	<Name>%s</Name>
	<Prefix/>
	<Marker/>
	<KeyCount>%d</KeyCount>
	<MaxKeys>1000</MaxKeys>
	<IsTruncated>false</IsTruncated>
	%s
</ListBucketResult>
		`, s.BucketName, len(s.Objects), contents)
	default:
		key, err := filepath.Rel("/"+s.BucketName, r.URL.Path)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		var found *Object
		for _, o := range s.Objects {
			if key == o.Key {
				found = o
			}
		}
		if found == nil {
			w.WriteHeader(404)
			return
		}

		etag := md5.Sum(found.Content)
		lastModified := strings.Replace(found.LastModified.UTC().Format(time.RFC1123), "UTC", "GMT", 1)

		w.Header().Add("Content-Type", found.ContentType)
		w.Header().Add("Last-Modified", lastModified)
		w.Header().Add("ETag", fmt.Sprintf("\"%x\"", etag))
		w.Header().Add("Content-Length", fmt.Sprintf("%d", len(found.Content)))

		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}

		w.WriteHeader(200)
		w.Write(found.Content)
	}
}
