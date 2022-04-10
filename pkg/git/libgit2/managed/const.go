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
)

var (
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
