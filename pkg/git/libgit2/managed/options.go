package managed

import (
	"sync"
)

// TransportOptions represents options to be applied at transport-level
// at request time.
type TransportOptions struct {
	TargetUrl string
	CABundle  []byte
}

var (
	transportOpts = make(map[string]TransportOptions, 0)
	m             sync.RWMutex
)

func AddTransportOptions(targetUrl string, opts TransportOptions) {
	m.Lock()
	transportOpts[targetUrl] = opts
	m.Unlock()
}

func RemoveTransportOptions(targetUrl string) {
	m.Lock()
	delete(transportOpts, targetUrl)
	m.Unlock()
}

func transportOptions(targetUrl string) (*TransportOptions, bool) {
	m.RLock()
	opts, found := transportOpts[targetUrl]
	m.RUnlock()

	if found {
		return &opts, true
	}
	return nil, false
}
