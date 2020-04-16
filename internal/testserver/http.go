package testserver

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
)

func NewTempHTTPServer() (*HTTP, error) {
	tmpDir, err := ioutil.TempDir("", "http-test-")
	if err != nil {
		return nil, err
	}
	srv := NewHTTPServer(tmpDir)
	return srv, nil
}

func NewHTTPServer(docroot string) *HTTP {
	root, err := filepath.Abs(docroot)
	if err != nil {
		panic(err)
	}
	return &HTTP{
		docroot: root,
	}
}

type HTTP struct {
	docroot    string
	middleware func(http.Handler) http.Handler
	server     *httptest.Server
}

func (s *HTTP) WithMiddleware(m func(handler http.Handler) http.Handler) *HTTP {
	s.middleware = m
	return s
}

func (s *HTTP) Start() {
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := http.FileServer(http.Dir(s.docroot))
		if s.middleware != nil {
			s.middleware(handler).ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}))
}

func (s *HTTP) Stop() {
	if s.server != nil {
		s.server.Close()
	}
}

func (s *HTTP) Root() string {
	return s.docroot
}
func (s *HTTP) URL() string {
	if s.server != nil {
		return s.server.URL
	}
	return ""
}
