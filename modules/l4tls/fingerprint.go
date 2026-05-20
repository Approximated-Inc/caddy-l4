// Package l4tls — TLS ClientHello fingerprinting (JA3 + JA4).
//
// JA4 follows the FoxIO spec, revision JA4-2024-12
// (https://github.com/FoxIO-LLC/ja4). "JA4" here means the default
// hashed form ja4_a_ja4_b_ja4_c with the cipher and extension lists
// SORTED (the variant that resists ClientHello field-order
// randomization). JA4_o (original order) and JA4_r (raw) are not
// computed.
//
// JA3 is the canonical Salesforce form (GREASE stripped from the
// cipher/extension/curve lists) for compatibility with public JA3
// threat-intel feeds.
//
// This file has no Caddy dependencies on purpose — it is pure
// computation over primitive slices so it can be unit-tested against
// the FoxIO vector corpus without a Caddy harness.
package l4tls

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// isGREASE reports whether v is a TLS GREASE value (RFC 8701):
// {0x0a0a, 0x1a1a, …, 0xfafa} — both bytes equal and each byte's low
// nibble is 0xA.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0x00ff
}

// JA3 returns the canonical Salesforce JA3 MD5 hex string (lowercase, 32
// chars): md5("Version,Ciphers,Extensions,EllipticCurves,ECPointFormats")
// where each list is a hyphen-joined run of decimal values and GREASE is
// stripped from the cipher/extension/curve lists.
func JA3(version uint16, cipherSuites, extensions, curves []uint16, pointFormats []uint8) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(version)))
	b.WriteByte(',')
	// GREASE filtered from ciphers/exts/curves per the canonical Salesforce
	// JA3 spec (https://github.com/salesforce/ja3) — verified against
	// Cloudflare's JA4 impl (https://blog.cloudflare.com/ja4-signals/).
	b.WriteString(joinUint16Dec(stripGREASE(cipherSuites)))
	b.WriteByte(',')
	b.WriteString(joinUint16Dec(stripGREASE(extensions)))
	b.WriteByte(',')
	b.WriteString(joinUint16Dec(stripGREASE(curves)))
	b.WriteByte(',')
	b.WriteString(joinUint8Dec(pointFormats)) // EC point formats have no GREASE values

	sum := md5.Sum([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// stripGREASE returns xs with all GREASE values removed. Shared by JA3
// (here) and JA4 (later); the single source of truth for GREASE filtering.
func stripGREASE(xs []uint16) []uint16 {
	out := make([]uint16, 0, len(xs))
	for _, x := range xs {
		if !isGREASE(x) {
			out = append(out, x)
		}
	}
	return out
}

func joinUint16Dec(xs []uint16) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(int(x))
	}
	return strings.Join(parts, "-")
}

func joinUint8Dec(xs []uint8) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(int(x))
	}
	return strings.Join(parts, "-")
}

// JA4 returns the default hashed JA4 string (e.g. t13d1516h2_…_…).
func JA4(in JA4Input) string {
	return "" // implemented in 3b.4
}

// JA4Input is the minimal set of ClientHello fields JA4 needs.
type JA4Input struct {
	SupportedVersions []uint16 // from supported_versions ext; falls back to legacy
	LegacyVersion     uint16
	CipherSuites      []uint16
	Extensions        []uint16 // wire order, GREASE kept
	SignatureAlgos    []uint16 // wire order
	ALPNs             []string
	SNIPresent        bool
}
