package hmacsha256

// key is zero padded to the block size of the hash function
// or hashed if longer than BlockLen
// ipad = 0x36 byte repeated for key length
// opad = 0x5c byte repeated for key length
// hmac = H([key ^ opad] H([key ^ ipad] text))

// Obj holds precomputed digest data for a given key.
type Obj struct {
	opad, ipad [BlockLen]byte
}

// Init initializes Obj with key.
func (h *Obj) Init(key []byte) {
	var bkey [BlockLen]byte
	if len(key) > BlockLen {
		var sha sha256Digest
		var digest [DigestLen]byte
		sha.reset()
		sha.hash(key)
		digest = sha.checkSum()
		copy(bkey[:], digest[:])

	} else {
		copy(bkey[:], key)
	}
	for i := range bkey {
		h.ipad[i] = bkey[i] ^ 0x36
		h.opad[i] = bkey[i] ^ 0x5C
	}
}

// Digest computes the HMAC-SHA-256 digest of the data slices and append the
// result to buf.
func (h *Obj) Digest(buf []byte, data ...[]byte) []byte {
	var digest [DigestLen]byte
	var sha sha256Digest
	sha.reset()
	sha.hash(h.ipad[:])
	for i := range data {
		sha.hash(data[i])
	}
	digest = sha.checkSum()
	sha.reset()
	sha.hash(h.opad[:])
	sha.hash(digest[:])
	digest = sha.checkSum()
	return append(buf, digest[:]...)
}

// Digest computes the HMAC-SHA-256 digest of the data slices using key, and
// append the result to buf.
func Digest(buf []byte, key []byte, data ...[]byte) []byte {
	var obj Obj
	obj.Init(key)
	return obj.Digest(buf, data...)
}

// Equal return true if d1 and d2 have both length DigestLen and all bytes are
// equal. Equal does't leak timing informtation when comparing d1 and d2.
func Equal(d1, d2 []byte) bool {
	if len(d1) != DigestLen || len(d1) != len(d2) {
		return false
	}
	var x byte
	for i := range d1 {
		x |= d1[i] ^ d2[i]
	}
	return x == 0
}
