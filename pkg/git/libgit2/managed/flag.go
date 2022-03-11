package managed

import (
	"os"
	"strings"
)

// Enabled defines whether the use of Managed Transport should be enabled.
// This is only affects git operations that uses libgit2 implementation.
//
// True is returned when the environment variable `EXPERIMENTAL_GIT_TRANSPORT`
// is detected with the value of `true` or `1`.
func Enabled() bool {
	if v, ok := os.LookupEnv("EXPERIMENTAL_GIT_TRANSPORT"); ok {
		return strings.ToLower(v) == "true" || v == "1"
	}
	return false
}
