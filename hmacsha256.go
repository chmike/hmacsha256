package hmacsha256

// DigestLen is the byte length of the sha256 digest.
const DigestLen = 32

// BlockLen is the byte length of the sha256 block.
const BlockLen = 64

const (
	chunk = 64
	init0 = 0x6A09E667
	init1 = 0xBB67AE85
	init2 = 0x3C6EF372
	init3 = 0xA54FF53A
	init4 = 0x510E527F
	init5 = 0x9B05688C
	init6 = 0x1F83D9AB
	init7 = 0x5BE0CD19
)

// sha256Digest represents the partial evaluation of a checksum.
type sha256Digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *sha256Digest) reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

func (d *sha256Digest) hash(p []byte) {
	d.len += uint64(len(p))
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
}

func (d *sha256Digest) checkSum() [DigestLen]byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.hash(tmp[0 : 56-len%64])
	} else {
		d.hash(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (56 - 8*i))
	}
	d.hash(tmp[0:8])

	h := d.h[:]

	var digest [DigestLen]byte
	for i, s := range h {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}

	return digest
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
