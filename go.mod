module github.com/fluxcd/source-controller

go 1.14

replace github.com/fluxcd/source-controller/api => ./api

require (
	github.com/blang/semver v3.5.0+incompatible
	github.com/fluxcd/pkg/gittestserver v0.0.2
	github.com/fluxcd/pkg/helmtestserver v0.0.1
	github.com/fluxcd/pkg/lockedfile v0.0.5
	github.com/fluxcd/pkg/recorder v0.0.5
	github.com/fluxcd/pkg/ssh v0.0.5
	github.com/fluxcd/source-controller/api v0.0.10
	github.com/go-git/go-billy/v5 v5.0.0
	github.com/go-git/go-git/v5 v5.1.0
	github.com/go-logr/logr v0.1.0
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.1
	go.uber.org/zap v1.13.0
	helm.sh/helm/v3 v3.3.0
	k8s.io/api v0.18.4
	k8s.io/apimachinery v0.18.4
	k8s.io/client-go v0.18.4
	sigs.k8s.io/controller-runtime v0.6.1
	sigs.k8s.io/yaml v1.2.0
)
