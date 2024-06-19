package pkgtesting

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/elazarl/goproxy"
	"gotest.tools/assert"
)

// NewHTTPProxy starts an HTTP proxy server in a random port and returns the
// URL of the proxy server and a function to stop the server.
// If httpsTargetAddr is not empty, the proxy server will handle CONNECT
// HTTPS requests to that address.
func NewHTTPProxy(t *testing.T, httpsTargetAddr string) (*url.URL, func()) {
	listener, err := net.Listen("tcp", ":0")
	assert.NilError(t, err, "could not start proxy server")

	addr := listener.Addr().String()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	if httpsTargetAddr != "" {
		proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return goproxy.OkConnect, httpsTargetAddr
		})
	}
	server := &http.Server{
		Addr:    addr,
		Handler: proxy,
	}

	go server.Serve(listener)
	return &url.URL{Scheme: "http", Host: addr}, func() {
		server.Shutdown(context.Background())
		listener.Close()
	}
}
