package controllers

import (
	"testing"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

func TestHasUpdated(t *testing.T) {
	tests := []struct {
		name     string
		current  []*sourcev1.Artifact
		updated  []*sourcev1.Artifact
		expected bool
	}{
		{
			name: "not updated single",
			current: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
			},
			updated: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
			},
			expected: false,
		},
		{
			name: "updated single",
			current: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
			},
			updated: []*sourcev1.Artifact{
				{
					Revision: "bar",
				},
			},
			expected: true,
		},
		{
			name: "not updated multiple",
			current: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			updated: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			expected: false,
		},
		{
			name: "updated multiple",
			current: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			updated: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
				{
					Revision: "baz",
				},
			},
			expected: true,
		},
		{
			name: "updated different artifact count",
			current: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			updated: []*sourcev1.Artifact{
				{
					Revision: "foo",
				},
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasArtifactUpdated(tt.current, tt.updated)
			if result != tt.expected {
				t.Errorf("Archive() result = %v, wantResult %v", result, tt.expected)
			}
		})
	}
}
