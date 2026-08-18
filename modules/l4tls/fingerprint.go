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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
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

// JA4 returns the default hashed JA4 string (e.g. t13d1516h2_…_…),
// FoxIO spec JA4-2024-12, sorted (default) form.
func JA4(in JA4Input) string {
	return ja4a(in) + "_" + ja4b(in.CipherSuites) + "_" + ja4c(in.Extensions, in.SignatureAlgos)
}

// ja4a builds the 10-char human-readable prefix t<vv><s><cc><ee><aa>.
// Not hashed, not sorted.
func ja4a(in JA4Input) string {
	ver := ja4Version(in.SupportedVersions, in.LegacyVersion)
	sni := "i"
	if in.SNIPresent {
		sni = "d"
	}
	nc := cap2(countNonGREASE(in.CipherSuites))
	ne := cap2(countNonGREASE(in.Extensions))
	transport := in.Transport
	if transport == 0 {
		transport = 't'
	}
	return fmt.Sprintf("%c%s%s%02d%02d%s", transport, ver, sni, nc, ne, ja4ALPN(in.ALPNs))
}

// ja4b is the cipher-suite hash component: GREASE removed, 4-hex, sorted
// ascending, comma-joined, first 12 hex of sha256. Empty list -> 12 zeros.
func ja4b(ciphers []uint16) string {
	xs := stripGREASE(ciphers)
	if len(xs) == 0 {
		return "000000000000"
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	return sha12(strings.Join(hex4(xs), ","))
}

// ja4c is the extension+sigalg hash component. Extensions: GREASE removed,
// then SNI(0x0000) and ALPN(0x0010) removed, sorted ascending. Sig algs:
// GREASE removed, ORIGINAL wire order (NOT sorted). Empty part -> 12 zeros.
func ja4c(extensions, sigAlgs []uint16) string {
	exts := stripGREASE(extensions)
	exts = removeValues(exts, 0x0000, 0x0010) // SNI + ALPN excluded from hash list (still counted in ee)
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	part := strings.Join(hex4(exts), ",")
	sa := stripGREASE(sigAlgs) // ORIGINAL order, NOT sorted
	if len(sa) > 0 {
		part += "_" + strings.Join(hex4(sa), ",")
	}
	if part == "" {
		return "000000000000"
	}
	return sha12(part)
}

// ja4Version maps the highest non-GREASE supported_version (or legacy
// fallback) to the JA4 two-char version code.
func ja4Version(supported []uint16, legacy uint16) string {
	best := uint16(0)
	for _, v := range supported {
		if isGREASE(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	if best == 0 {
		best = legacy
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

// ja4ALPN returns the 2-char ALPN code. No ALPN -> "00"; non-ASCII first
// byte of the first ALPN value -> "99"; else first+last byte of that value.
func ja4ALPN(alpns []string) string {
	if len(alpns) == 0 || alpns[0] == "" {
		return "00"
	}
	s := alpns[0]
	if s[0] > 0x7f { // non-ASCII first byte -> FoxIO emits "99"
		return "99"
	}
	return string([]byte{s[0], s[len(s)-1]})
}

func countNonGREASE(xs []uint16) int {
	n := 0
	for _, x := range xs {
		if !isGREASE(x) {
			n++
		}
	}
	return n
}

func cap2(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func removeValues(xs []uint16, drop ...uint16) []uint16 {
	out := xs[:0:0]
	for _, x := range xs {
		skip := false
		for _, d := range drop {
			if x == d {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, x)
		}
	}
	return out
}

func hex4(xs []uint16) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = fmt.Sprintf("%04x", x)
	}
	return out
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ja4InputFromCHI adapts a parsed ClientHelloInfo (returned by value) into
// the JA4Input the JA4 computation needs.
func ja4InputFromCHI(chi ClientHelloInfo) JA4Input {
	return JA4Input{
		SupportedVersions: chi.SupportedVersions,
		LegacyVersion:     chi.Version,
		CipherSuites:      chi.CipherSuites,
		Extensions:        chi.Extensions,
		SignatureAlgos:    sigSchemesToUint16(chi.SignatureSchemes),
		ALPNs:             chi.SupportedProtos,
		SNIPresent:        containsValue(chi.Extensions, 0x0000),
	}
}

func sigSchemesToUint16(ss []tls.SignatureScheme) []uint16 {
	out := make([]uint16, len(ss))
	for i, s := range ss {
		out[i] = uint16(s)
	}
	return out
}

func curveIDsToUint16(cs []tls.CurveID) []uint16 {
	out := make([]uint16, len(cs))
	for i, c := range cs {
		out[i] = uint16(c)
	}
	return out
}

func containsValue(xs []uint16, want uint16) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
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
	// Transport is the JA4_a leading character: 't' for TLS over TCP, 'q' for
	// QUIC, 'd' for DTLS. The zero value is treated as 't', so existing
	// callers and the vendored FoxIO vectors are unaffected.
	Transport byte
}
