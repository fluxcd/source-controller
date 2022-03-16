package chart

import (
	"os"
	"testing"

	. "github.com/onsi/gomega"
)

func Test_verifyChartWithProvFile(t *testing.T) {
	g := NewWithT(t)

	keyring, err := os.Open("../testdata/charts/pub.gpg")
	g.Expect(err).ToNot(HaveOccurred())
	ver, err := verifyChartWithProvFile(keyring, "../testdata/charts/helmchart-0.1.0.tgz", "../testdata/charts/helmchart-0.1.0.tgz.prov")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ver).ToNot(BeNil())
}
