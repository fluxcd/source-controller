package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/go-git/go-git/v5/plumbing/transport"
	httptransport "github.com/go-git/go-git/v5/plumbing/transport/http"
	ctrl "sigs.k8s.io/controller-runtime"
)

// HttpTransportWithCustomCerts returns an HTTP transport with custom certificates and CA.
func HttpTransportwithCustomCerts(tlsConfig *tls.Config, ctx context.Context) (transport.Transport, error) {

	log := ctrl.LoggerFrom(ctx)
	var err error
	// ensure the certificate are there
	// CA is optional
	if tlsConfig == nil || len(tlsConfig.Certificates) == 0 {
		log.Error(err, "tlsConfig cannot be nil or empty")

		return nil, fmt.Errorf("tlsConfig cannot be nil or empty")
	}

	return httptransport.NewClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}), nil

}
