package repository

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "with slash",
			url:  "http://example.com/",
			want: "http://example.com/",
		},
		{
			name: "without slash",
			url:  "http://example.com",
			want: "http://example.com/",
		},
		{
			name: "double slash",
			url:  "http://example.com//",
			want: "http://example.com/",
		},
		{
			name: "empty",
			url:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got := NormalizeURL(tt.url)
			g.Expect(got).To(Equal(tt.want))
		})
	}
}
