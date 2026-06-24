/*
Copyright 2024 The Flux authors

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

package testlistener

import (
	"net"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

// New creates a TCP listener on a random port and returns
// the listener, the address and the port of this listener.
// It also registers a cleanup function to close the listener
// when the test ends.
func New(t *testing.T) (net.Listener, string, int) {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() { lis.Close() })

	addr := lis.Addr().String()
	addrParts := strings.Split(addr, ":")
	portStr := addrParts[len(addrParts)-1]
	port, err := strconv.Atoi(portStr)
	g.Expect(err).NotTo(HaveOccurred())

	return lis, addr, port
}
