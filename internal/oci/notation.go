package oci

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-go/dir"
	verifier "github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/truststore"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	oras "oras.land/oras-go/v2/registry/remote"
	oauth "oras.land/oras-go/v2/registry/remote/auth"
)

// notationOptions is a struct that holds options for notation verifier
type notationOptions struct {
	PublicKey  []byte
	TrustStore *trustpolicy.Document
	Keychain   authn.Keychain
	ROpt       []remote.Option
}

// NotationOptions is a function that configures the options applied to a notation verifier
type NotationOptions func(opts *notationOptions)

// WithTrustStore sets the trust store configuration.
func WithTrustStore(trustStore *trustpolicy.Document) NotationOptions {
	return func(opts *notationOptions) {
		opts.TrustStore = trustStore
	}
}

// WithNotaryPublicKey sets the public key.
func WithNotaryPublicKey(publicKey []byte) NotationOptions {
	return func(opts *notationOptions) {
		opts.PublicKey = publicKey
	}
}

// WithNotaryRemoteOptions is a functional option for overriding the default
// remote options used by the verifier
func WithNotaryRemoteOptions(opts ...remote.Option) NotationOptions {
	return func(o *notationOptions) {
		o.ROpt = opts
	}
}

// WithNotaryKeychain is a functional option for overriding the default
// remote options used by the verifier
func WithNotaryKeychain(key authn.Keychain) NotationOptions {
	return func(o *notationOptions) {
		o.Keychain = key
	}
}

// NotatryVerifier is a struct which is responsible for executing verification logic
type NotaryVerifier struct {
	auth     authn.Keychain
	verifier *notation.Verifier
	opts     []remote.Option
}

// NewNotaryVerifier initializes a new NotaryVerifier
func NewNotaryVerifier(opts ...NotationOptions) (*NotaryVerifier, error) {
	o := notationOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	for _, pol := range o.TrustStore.TrustPolicies {
		certName := pol.Name
		for _, store := range pol.TrustStores {
			s := strings.Split(store, ":")
			if len(s) < 1 {
				return nil, fmt.Errorf("URL must not contain a tag; remove ':%s'", s[1])
			}
			generateTrustStore(s[0], s[1], certName, o.PublicKey)
		}
	}

	verifier, err := verifier.New(o.TrustStore, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		return nil, err
	}

	return &NotaryVerifier{
		auth:     o.Keychain,
		verifier: &verifier,
		opts:     o.ROpt,
	}, nil
}

// Verify verifies the authenticity of the given ref OCI image.
// It returns a boolean indicating if the verification was successful.
// It returns an error if the verification fails, nil otherwise.
func (v *NotaryVerifier) Verify(ctx context.Context, ref name.Reference) (bool, error) {
	url := ref.Name()
	remoteRepo, err := oras.NewRepository(url)
	if err != nil {
		return false, err
	}
	repo := registry.NewRepository(remoteRepo)

	ss := stringResource{url}

	au, err := v.auth.Resolve(ss)
	authConfig, err := au.Authorization()

	credentialProvider := func(ctx context.Context, registry string) (oauth.Credential, error) {
		if authConfig.Username != "" || authConfig.Password != "" || authConfig.IdentityToken != "" {
			return oauth.Credential{
				Username:     authConfig.Username,
				Password:     authConfig.Password,
				RefreshToken: authConfig.IdentityToken,
			}, nil
		}
		return oauth.EmptyCredential, nil
	}

	repoClient := &oauth.Client{
		Header: http.Header{
			"User-Agent": {"flux"},
		},
		Cache:      oauth.NewCache(),
		Credential: credentialProvider,
	}

	remoteRepo.Client = repoClient

	i, err := remote.Image(ref, v.opts...)

	log.Println(i.ConfigFile())
	d, err := i.Digest()

	repoUrl := ""

	if s := strings.Split(url, ":"); len(s) == 2 && !strings.Contains(url, "@") {
		repoUrl = fmt.Sprintf("%s@%s", s[0], d)
	}

	verifyOptions := notation.VerifyOptions{
		ArtifactReference:    repoUrl,
		MaxSignatureAttempts: 50,
	}

	_, signatures, err := notation.Verify(ctx, *v.verifier, repo, verifyOptions)

	if err != nil {
		return false, err
	}

	if len(signatures) == 0 {
		return false, nil
	}

	return true, nil
}

func generateTrustStore(storeType string, storeName string, certName string, cert []byte) error {
	// changing the path of the trust store for demo purpose.
	// Users could keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "tmp"
	directory := fmt.Sprintf("tmp/truststore/x509/%s/%s", storeType, storeName)
	certFile := fmt.Sprintf("%s/%s.pem", directory, certName)

	// Adding the certificate into the trust store.
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	return os.WriteFile(certFile, cert, 0600)
}

type stringResource struct {
	registry string
}

func (r stringResource) String() string {
	return r.registry
}

func (r stringResource) RegistryStr() string {
	return strings.Split(r.registry, "/")[0]
}
