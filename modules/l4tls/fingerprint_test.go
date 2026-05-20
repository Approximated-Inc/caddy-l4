package l4tls

import (
	"os"
	"testing"
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

func TestJA3_emptyLists(t *testing.T) {
	// version only, everything else empty -> "769,,,,"
	got := JA3(0x0301, nil, nil, nil, nil)
	want := "f5d1076d0d11b5cd81c4c4e8e8ee881a" // md5("769,,,,")
	if got != want {
		t.Errorf("JA3 empty = %q, want %q", got, want)
	}
}
