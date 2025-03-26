package controller

import (
	"context"
	"crypto/tls"
	"testing"

	. "github.com/onsi/gomega"
)

func TestHttpTransportwithCustomCerts(t *testing.T) {

	// Create test context
	ctx := context.Background()

	t.Run("with valid TLS config", func(t *testing.T) {
		g := NewWithT(t)

		// Create test certificate
		certs, _ := tls.LoadX509KeyPair("./testdata/certs/client.pem", "./testdata/certs/client-key.pem")

		// Create test TLS config
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{certs},
		}

		// Call function
		transport, err := HttpTransportwithCustomCerts(tlsConfig, ctx)

		// Assert results using Gomega
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(transport).NotTo(BeNil())
	})

	t.Run("with nil TLS config", func(t *testing.T) {
		g := NewWithT(t)

		// Call function with nil config
		transport, err := HttpTransportwithCustomCerts(nil, ctx)

		// Assert results using Gomega
		g.Expect(err).ToNot(BeNil())
		g.Expect(transport).To(BeNil())
	})

	t.Run("with empty certificates", func(t *testing.T) {
		g := NewWithT(t)

		// Create empty TLS config
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{},
		}

		// Call function
		transport, err := HttpTransportwithCustomCerts(tlsConfig, ctx)

		// Assert results using Gomega
		g.Expect(err).ToNot(BeNil())
		g.Expect(transport).To(BeNil())
	})
}
