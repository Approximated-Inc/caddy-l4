// Package l4tls — TLS ClientHello fingerprinting (JA3 + JA4).
//
// JA4 follows the FoxIO spec, revision JA4-2024-12
// (https://github.com/FoxIO-LLC/ja4). "JA4" here means the default
// hashed form ja4_a_ja4_b_ja4_c with the cipher and extension lists
// SORTED (the variant that resists ClientHello field-order
// randomization). JA4_o (original order) and JA4_r (raw) are not
// computed.
//
// JA3 is the classic Salesforce form (GREASE NOT stripped) for
// compatibility with public JA3 threat-intel feeds.
//
// This file has no Caddy dependencies on purpose — it is pure
// computation over primitive slices so it can be unit-tested against
// the FoxIO vector corpus without a Caddy harness.
package l4tls

// isGREASE reports whether v is a TLS GREASE value (RFC 8701):
// {0x0a0a, 0x1a1a, …, 0xfafa} — both bytes equal and each byte's low
// nibble is 0xA.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0x00ff
}

// JA3 returns the classic JA3 MD5 hex string (lowercase, 32 chars).
func JA3(version uint16, cipherSuites, extensions, curves []uint16, pointFormats []uint8) string {
	return "" // implemented in 3b.2
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
