package git

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
)

func TestCheckoutTagSemVer_Checkout(t *testing.T) {
	tag := CheckoutTag{
		tag: "v1.7.0",
	}
	tmpDir, _ := ioutil.TempDir("", "test")
	defer os.RemoveAll(tmpDir)

	cTag, _, err := tag.Checkout(context.TODO(), tmpDir, "https://github.com/projectcontour/contour", nil)
	if err != nil {
		t.Error(err)
	}

	semVer := CheckoutSemVer{
		semVer: ">=1.0.0 <=1.7.0",
	}
	tmpDir2, _ := ioutil.TempDir("", "test")
	defer os.RemoveAll(tmpDir2)

	cSemVer, _, err := semVer.Checkout(context.TODO(), tmpDir2, "https://github.com/projectcontour/contour", nil)
	if err != nil {
		t.Error(err)
	}

	if cTag.Hash.String() != cSemVer.Hash.String() {
		t.Errorf("expected semver hash %s, got %s", cTag.Hash.String(), cSemVer.Hash.String())
	}
}
