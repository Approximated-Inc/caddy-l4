package l4tls

import (
	"encoding/hex"
	"net"
	"os"
	"testing"

	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func TestIsGREASE(t *testing.T) {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x8a8a, 0xfafa}
	for _, v := range grease {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}
	notGrease := []uint16{0x0000, 0x1301, 0x0a0b, 0x1a2a, 0xc02f}
	for _, v := range notGrease {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}

func TestParseRawClientHello_TLS13_VersionField(t *testing.T) {
	raw, err := os.ReadFile("testdata/clienthello_tls13.bin")
	if err != nil {
		t.Fatalf("read TLS1.3 fixture: %v", err)
	}
	info := parseRawClientHello(raw)
	// legacy_version per RFC 8446 §4.1.2 — modern TLS 1.3 clients put 0x0303
	// here; the real version lives in the supported_versions extension.
	// parsehello.go:43 reads this raw wire field via s.ReadUint16(&info.Version).
	// If this fails, parseRawClientHello regressed (e.g. "fixed" to use the
	// effective negotiated version, like the Caddy ja3ja4 plugin's documented
	// bug), which would silently break every TLS 1.3 JA3 against public feeds.
	if info.Version != 0x0303 {
		t.Errorf("info.Version = %#04x, want 0x0303 (legacy_version)", info.Version)
	}
}

func TestJA3_basic(t *testing.T) {
	// Hand vector: TLS1.0 legacy=769 (0x0301), ciphers [0xc02f, 0xc030],
	// exts [0x0000, 0x0017], curves [0x001d], pointfmt [0x00]. No GREASE.
	// JA3 string = "769,49199-49200,0-23,29,0"
	got := JA3(0x0301, []uint16{0xc02f, 0xc030}, []uint16{0x0000, 0x0017}, []uint16{0x001d}, []uint8{0x00})
	want := "5554b501f9780eb0c0e92ffa299d3539" // md5("769,49199-49200,0-23,29,0")
	if got != want {
		t.Errorf("JA3 = %q, want %q", got, want)
	}
}

func TestJA3_stripsGREASE(t *testing.T) {
	// Same client with and without GREASE in cipher/ext/curve lists must
	// produce the SAME JA3 (the whole point of GREASE filtering).
	withG := JA3(0x0301,
		[]uint16{0x0a0a, 0xc02f, 0xc030},
		[]uint16{0x1a1a, 0x0000, 0x0017},
		[]uint16{0x2a2a, 0x001d},
		[]uint8{0x00})
	without := JA3(0x0301, []uint16{0xc02f, 0xc030}, []uint16{0x0000, 0x0017}, []uint16{0x001d}, []uint8{0x00})
	if withG != without {
		t.Errorf("GREASE not filtered: withGREASE=%q != withoutGREASE=%q", withG, without)
	}
}

func TestVectorsParse(t *testing.T) {
	if len(JAVectors) == 0 {
		t.Skip("no vectors vendored yet")
	}
	for _, v := range JAVectors {
		raw, err := hex.DecodeString(v.ClientHello)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", v.Name, err)
		}
		chi := parseRawClientHello(raw)
		if len(chi.CipherSuites) == 0 {
			t.Errorf("%s: parser produced no cipher suites", v.Name)
		}
	}
}

func TestJA4_vectors(t *testing.T) {
	if len(JAVectors) == 0 {
		t.Skip("no vectors vendored")
	}
	for _, v := range JAVectors {
		if v.ExpectedJA4 == "" {
			continue
		}
		raw, err := hex.DecodeString(v.ClientHello)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", v.Name, err)
		}
		chi := parseRawClientHello(raw)
		got := JA4(ja4InputFromCHI(chi))
		if got != v.ExpectedJA4 {
			t.Errorf("%s: JA4 = %q, want %q", v.Name, got, v.ExpectedJA4)
		}
	}
}

func TestJA3_vectors(t *testing.T) {
	if len(JAVectors) == 0 {
		t.Skip("no vectors vendored")
	}
	for _, v := range JAVectors {
		if v.ExpectedJA3 == "" {
			continue // JA3 not asserted for this vector
		}
		raw, _ := hex.DecodeString(v.ClientHello)
		chi := parseRawClientHello(raw)
		got := JA3(chi.Version, chi.CipherSuites, chi.Extensions,
			curveIDsToUint16(chi.SupportedCurves), chi.SupportedPoints)
		if got != v.ExpectedJA3 {
			t.Errorf("%s: JA3 = %q, want %q", v.Name, got, v.ExpectedJA3)
		}
	}
}

func TestJA4a_encoding(t *testing.T) {
	in := JA4Input{
		SupportedVersions: []uint16{0x0a0a, 0x0304, 0x0303},
		CipherSuites:      append([]uint16{0x0a0a}, make([]uint16, 15)...),
		Extensions:        append([]uint16{0x1a1a}, make([]uint16, 16)...),
		ALPNs:             []string{"h2"},
		SNIPresent:        true,
	}
	if got := ja4a(in); got != "t13d1516h2" {
		t.Errorf("ja4a = %q, want t13d1516h2", got)
	}
}

func TestJA4_countCap(t *testing.T) {
	many := make([]uint16, 120)
	for i := range many {
		many[i] = uint16(0x1300 + i)
	}
	in := JA4Input{SupportedVersions: []uint16{0x0304}, CipherSuites: many, Extensions: many, ALPNs: nil, SNIPresent: false}
	if got := ja4a(in); got != "t13i9999"+"00" {
		t.Errorf("ja4a = %q, want t13i999900", got)
	}
}

func TestJA4c_noSigAlgs(t *testing.T) {
	got := ja4c([]uint16{0x0017, 0x0000, 0x0010, 0x002b}, nil)
	want := sha12("0017,002b") // 0000 + 0010 removed, sorted
	if got != want {
		t.Errorf("ja4c noSig = %q, want %q", got, want)
	}
}

func TestJA4_emptySentinels(t *testing.T) {
	if got := ja4b(nil); got != "000000000000" {
		t.Errorf("ja4b(nil) = %q, want 000000000000", got)
	}
	if got := ja4b([]uint16{0x0a0a}); got != "000000000000" { // only GREASE -> empty after strip
		t.Errorf("ja4b(GREASE-only) = %q, want 000000000000", got)
	}
	if got := ja4c(nil, nil); got != "000000000000" {
		t.Errorf("ja4c(nil,nil) = %q, want 000000000000", got)
	}
}

func TestJA3_emptyLists(t *testing.T) {
	// version only, everything else empty -> "769,,,,"
	got := JA3(0x0301, nil, nil, nil, nil)
	want := "f5d1076d0d11b5cd81c4c4e8e8ee881a" // md5("769,,,,")
	if got != want {
		t.Errorf("JA3 empty = %q, want %q", got, want)
	}
}

func TestMatch_setsFingerprintVars(t *testing.T) {
	if len(JAVectors) == 0 {
		t.Skip("no vectors")
	}
	v := JAVectors[0] // firefox_tls13_no_grease: has both ExpectedJA3 + ExpectedJA4
	hello, err := hex.DecodeString(v.ClientHello)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	// Frame as one TLS handshake record: type=0x16, version=0x0301, len(hello).
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)

	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()
	cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())
	defer cx.Close()

	go func() {
		_, _ = in.Write(rec)
	}()

	m := &MatchTLS{}
	m.logger = zap.NewNop()

	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if !matched {
		t.Fatal("expected match with no sub-matchers")
	}
	if got := cx.GetVar("tls_ja3"); got != v.ExpectedJA3 {
		t.Errorf("tls_ja3 = %v, want %v", got, v.ExpectedJA3)
	}
	if got := cx.GetVar("tls_ja4"); got != v.ExpectedJA4 {
		t.Errorf("tls_ja4 = %v, want %v", got, v.ExpectedJA4)
	}
}

func TestJA4_transportPrefix(t *testing.T) {
	base := JA4Input{
		SupportedVersions: []uint16{0x0304},
		CipherSuites:      []uint16{0x1301, 0x1302},
		Extensions:        []uint16{0x0000, 0x0010},
		SignatureAlgos:    []uint16{0x0403},
		ALPNs:             []string{"h2"},
		SNIPresent:        true,
	}

	cases := []struct {
		name      string
		transport byte
		wantFirst byte
	}{
		{"zero value defaults to tcp", 0, 't'},
		{"explicit tcp", 't', 't'},
		{"quic", 'q', 'q'},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			in.Transport = c.transport
			got := JA4(in)
			if got[0] != c.wantFirst {
				t.Errorf("JA4 = %q, first byte = %q, want %q", got, got[0], c.wantFirst)
			}
		})
	}
}

func TestJA4_transportOnlyChangesFirstByte(t *testing.T) {
	in := JA4Input{
		SupportedVersions: []uint16{0x0304},
		CipherSuites:      []uint16{0x1301},
		Extensions:        []uint16{0x0000},
		SignatureAlgos:    []uint16{0x0403},
		SNIPresent:        true,
	}
	tcp := JA4(in)
	in.Transport = 'q'
	quic := JA4(in)

	if tcp[1:] != quic[1:] {
		t.Errorf("transport changed more than the first byte:\n tcp = %q\nquic = %q", tcp, quic)
	}
}
