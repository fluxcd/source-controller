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

package managed

import (
	"net/url"
)

// EnsureProtocol returns targetURL with the correct SSH or HTTP protocol.
//
// It takes into account whether targetURL includes opt-in protocols
// ssh+unmanaged or ssh+managed. For automatic upgrade, it must be
// enabled at controller level and the target domain must not be in
// the deny list.
//
// If targetURL is not a valid URL, itself is returned.
func EnsureProtocol(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	// opt-in unmanaged SSH, change scheme to ssh://
	if u.Scheme == SSHUnmanagedProtocol {
		u.Scheme = SSHProtocol
		return u.String()
	}
	// opt-in managed SSH
	if u.Scheme == SSHManagedProtocol {
		return u.String()
	}
	// ignore other SSH protocols (i.e. ssh+git / git+ssh)
	if u.Scheme == SSHGitProtocol || u.Scheme == GitSSHProtocol {
		return u.String()
	}
	// auto upgrade to managed transport
	if u.Scheme == SSHProtocol && upgradeToManagedSSH(u.Hostname()) {
		u.Scheme = SSHManagedProtocol
		return u.String()
	}

	// opt-in unmanaged HTTP, change scheme to http://
	if u.Scheme == HTTPUnmanagedProtocol {
		u.Scheme = HTTPProtocol
		return u.String()
	}
	// opt-in unmanaged HTTPS, change scheme to https://
	if u.Scheme == HTTPSUnmanagedProtocol {
		u.Scheme = HTTPSProtocol
		return u.String()
	}
	// opt-in managed HTTP
	if u.Scheme == HTTPManagedProtocol {
		return u.String()
	}
	// opt-in managed HTTPS
	if u.Scheme == HTTPSManagedProtocol {
		return u.String()
	}
	// auto upgrade to managed transport
	if Enabled() && u.Scheme == HTTPProtocol {
		u.Scheme = HTTPManagedProtocol
		return u.String()
	}
	if Enabled() && u.Scheme == HTTPSProtocol {
		u.Scheme = HTTPSManagedProtocol
		return u.String()
	}

	return u.String()
}

func upgradeToManagedSSH(hostName string) bool {
	return Enabled() && !HasAnySuffix(denySSHAutoUpgradeDomains, hostName)
}
