package controller

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/go-git/go-git/v5/plumbing/transport"
	httptransport "github.com/go-git/go-git/v5/plumbing/transport/http"
	ctrl "sigs.k8s.io/controller-runtime"
)

// HttpTransportWithCustomCerts returns an HTTP transport with custom certificates.
// If proxyStr is provided, it will be used as the proxy URL.
// If not, it tries to fetch the proxy from an environment variable.
func HttpTransportwithCustomCerts(tlsConfig *tls.Config, proxyStr *transport.ProxyOptions, ctx context.Context) (transport.Transport, error) {

	log := ctrl.LoggerFrom(ctx)
	// var message string

	if tlsConfig == nil || len(tlsConfig.Certificates) == 0 {
		log.Info("tlsConfig cannot be nil")
		return nil, nil
	}

	return httptransport.NewClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}), nil

}