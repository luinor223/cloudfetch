package cloudfetch

import (
	"slices"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestChrome156Spec(t *testing.T) {
	spec, err := chrome156()
	if err != nil {
		t.Fatal(err)
	}
	exts := spec.Extensions
	for _, i := range []int{0, len(exts) - 1} {
		if _, ok := exts[i].(*utls.UtlsGREASEExtension); !ok {
			t.Errorf("extension %d = %T, want GREASE", i, exts[i])
		}
	}
	if !slices.ContainsFunc(exts, func(e utls.TLSExtension) bool {
		g, ok := e.(*utls.GenericExtension)
		return ok && g.Id == extTrustAnchorIDs && len(g.Data) == len(trustAnchorIDs)
	}) {
		t.Error("missing Trust Anchor IDs extension")
	}

	i := slices.IndexFunc(exts, func(e utls.TLSExtension) bool {
		_, ok := e.(*utls.SignatureAlgorithmsExtension)
		return ok
	})
	if i < 0 {
		t.Fatal("missing signature_algorithms")
	}
	algs := exts[i].(*utls.SignatureAlgorithmsExtension).SupportedSignatureAlgorithms
	if g := uint16(algs[0]); g&0x0f0f != 0x0a0a || g>>8 != g&0xff {
		t.Errorf("first signature algorithm = %#04x, want GREASE", g)
	}
	if !slices.Equal(algs[1:4], mlDSA) {
		t.Errorf("signature algorithms = %v, want ML-DSA after GREASE", algs)
	}

	// Each call must build fresh extensions, since a handshake mutates them.
	again, _ := chrome156()
	if &again.Extensions[0] == &spec.Extensions[0] {
		t.Error("chrome156 reused the extension slice")
	}
}
