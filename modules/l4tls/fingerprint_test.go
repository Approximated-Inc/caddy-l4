package l4tls

import "testing"

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
