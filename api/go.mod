module github.com/fluxcd/source-controller/api

go 1.16

require (
	github.com/fluxcd/pkg/apis/acl v0.0.1
	github.com/fluxcd/pkg/apis/meta v0.11.0-rc.1
	// TODO(hidde): introduction of the runtime package is temporary, and the dependency should be removed as soon as
	//  all APIs have been updated to the runtime standards (more specifically; have dropped their condition modifying
	//  functions).
	github.com/fluxcd/pkg/runtime v0.13.0-rc.3
	k8s.io/apimachinery v0.22.2
	sigs.k8s.io/controller-runtime v0.10.2
)
