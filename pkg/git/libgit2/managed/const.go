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

const (
	// URLMaxLength represents the max length for the entire URL
	// when cloning Git repositories via HTTP(S).
	URLMaxLength = 2048

	// PathMaxLength represents the max length for the path element
	// when cloning Git repositories via SSH.
	PathMaxLength = 4096

	// HTTPProtocol represents the HTTP protocol.
	HTTPProtocol string = "http"

	// HTTPSProtocol represents the HTTPS protocol.
	HTTPSProtocol string = "https"

	// SSHProtocol represents the SSH protocol.
	SSHProtocol string = "ssh"

	// SSHGitProtocol represents the ssh+git protocol.
	SSHGitProtocol string = "ssh+git"

	// GitSSHProtocol represents the git+ssh protocol.
	GitSSHProtocol string = "git+ssh"

	// HTTPManagedProtocol represents the HTTP managed protocol.
	// It can be used to opt-in HTTP URLs over Managed Transport.
	HTTPManagedProtocol string = "http+managed"

	// HTTPUnmanagedProtocol represents the HTTP unmanaged protocol.
	// It can be used to opt-out HTTP URLs over Managed Transport.
	HTTPUnmanagedProtocol string = "http+unmanaged"

	// HTTPSManagedProtocol represents the HTTPS managed protocol.
	// It can be used to opt-in HTTPS URLs over Managed Transport.
	HTTPSManagedProtocol string = "https+managed"

	// HTTPSUnmanagedProtocol represents the HTTPS unmanaged protocol.
	// It can be used to opt-out HTTPS URLs over Managed Transport.
	HTTPSUnmanagedProtocol string = "https+unmanaged"

	// SSHManagedProtocol represents the SSH managed protocol.
	// It can be used to opt-in SSH URLs over Managed Transport.
	SSHManagedProtocol string = "ssh+managed"

	// SSHUnmanagedProtocol represents the SSH unmanaged protocol.
	// It can be used to opt-out SSH URLs over Managed Transport.
	SSHUnmanagedProtocol string = "ssh+unmanaged"
)

var (
	// denySSHAutoUpgradeDomains is a list of domains that cannot be
	// supported in managed transport via SSH.
	denySSHAutoUpgradeDomains = []string{
		// DevOps requires the Git protocol capabilities (e.g. multi_ack
		// and multi_ack_detailed) that are not fully supported by libgit2/git2go
		// in managed transport mode.
		"dev.azure.com",
	}

	// denyConcurrentConnections is a list of servers (<DOMAIN>:<PORT>)
	// that should use single-use connections.
	//
	// Some servers do not support concurrent connections
	// (e.g. public bitbucket.org accounts) and may struggle with
	// multiple sessions within the same connection. Avoid such problems
	// by closing the connection as soon as they are no longer needed.
	denyConcurrentConnections = []string{
		"bitbucket.org:22",
	}
)
