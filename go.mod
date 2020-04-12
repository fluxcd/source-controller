module github.com/fluxcd/source-controller

go 1.13

require (
	github.com/blang/semver v3.5.0+incompatible
	github.com/go-git/go-git/v5 v5.0.0
	github.com/go-logr/logr v0.1.0
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/pkg/errors v0.9.1
	helm.sh/helm/v3 v3.1.2
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v0.17.2
	rsc.io/letsencrypt v0.0.3 // indirect
	sigs.k8s.io/controller-runtime v0.5.0
	sigs.k8s.io/yaml v1.1.0
)
