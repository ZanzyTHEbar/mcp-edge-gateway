package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"time"
)

// New returns a RFC 9562 UUID version 7 as UUID type.
func New() UUID {
	var u UUID
	ms := uint64(time.Now().UnixMilli())
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	_, _ = rand.Read(u[6:])
	u[6] = (u[6] & 0x0f) | 0x70
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

// DeriveV7 returns a deterministic UUIDv7 with timestamp bits from at and
// random bits derived from namespace and seed.
func DeriveV7(at time.Time, namespace string, seed string) UUID {
	var u UUID
	ms := uint64(at.UTC().UnixMilli())
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	sum := sha256.Sum256([]byte(namespace + "\x00" + seed))
	copy(u[6:], sum[:10])
	u[6] = (u[6] & 0x0f) | 0x70
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

func encodeCanonical(u [16]byte) string {
	var dst [36]byte
	hex := func(b byte) (byte, byte) {
		const hexdigits = "0123456789abcdef"
		return hexdigits[b>>4], hexdigits[b&0x0f]
	}
	writeByte := func(off int, b byte) int {
		h, l := hex(b)
		dst[off] = h
		dst[off+1] = l
		return off + 2
	}
	o := 0
	for i := 0; i < 4; i++ {
		o = writeByte(o, u[i])
	}
	dst[o] = '-'
	o++
	for i := 4; i < 6; i++ {
		o = writeByte(o, u[i])
	}
	dst[o] = '-'
	o++
	for i := 6; i < 8; i++ {
		o = writeByte(o, u[i])
	}
	dst[o] = '-'
	o++
	for i := 8; i < 10; i++ {
		o = writeByte(o, u[i])
	}
	dst[o] = '-'
	o++
	for i := 10; i < 16; i++ {
		o = writeByte(o, u[i])
	}
	return string(dst[:])
}
