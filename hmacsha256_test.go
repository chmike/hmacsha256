package hmacsha256

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestSha256(t *testing.T) {
	for i := 0; i < 20; i++ {
		sha1 := sha256.New()
		var sha2 sha256Digest
		sha2.reset()
		for j := 0; j < i; j++ {
			var b = []byte(strings.Repeat("test ", i*10))
			sha1.Write(b)
			sha2.hash(b)
		}
		var d2 = sha2.checkSum()
		if !Equal(sha1.Sum(nil), d2[:]) {
			t.Errorf("digest mismatch with i: %d ", i)
		}
	}
}

func TestHmacSha256Key16(t *testing.T) {
	var key = make([]byte, 16)
	var h = hmac.New(sha256.New, key)
	var data = []byte(strings.Repeat("test ", 100))
	h.Write(data)
	if !Equal(h.Sum(nil), Digest(nil, key, data)) {
		t.Errorf("hmac sha256 digest mismatch")
	}
}

func TestHmacSha256Key128(t *testing.T) {
	var key = make([]byte, 128)
	var h = hmac.New(sha256.New, key)
	var data1 = []byte(strings.Repeat("test ", 100))
	h.Write(data1)
	if !Equal(h.Sum(nil), Digest(nil, key, data1)) {
		t.Errorf("hmac sha256 digest mismatch")
	}
	var data2 = make([]byte, 57)
	h.Reset()
	h.Write(data2)
	if !Equal(h.Sum(nil), Digest(nil, key, data2)) {
		t.Errorf("hmac sha256 digest mismatch")
	}
}

func TestHForFullCoverage(t *testing.T) {
	var buf = make([]byte, DigestLen)
	if Equal(buf, buf[1:]) {
		t.Errorf("expected Equal return false")
	}
	var key = make([]byte, 16)
	var data = make([]byte, 57)
	var h = hmac.New(sha256.New, key)
	h.Write(data)
	if !Equal(h.Sum(nil), Digest(nil, key, data)) {
		t.Errorf("hmac sha256 digest mismatch")
	}
}

var res []byte

func BenchmarkStdSha256(b *testing.B) {
	var buf = make([]byte, DigestLen)
	var data = []byte(strings.Repeat("test ", 10))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		sha := sha256.New()
		for i := 0; i < 10; i++ {
			sha.Write(data)
		}
		res = sha.Sum(buf[:0])
	}
}

func BenchmarkLocSha256(b *testing.B) {
	buf := make([]byte, DigestLen)
	data := []byte(strings.Repeat("test ", 10))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var sha sha256Digest
		sha.reset()
		for i := 0; i < 10; i++ {
			sha.hash(data)
		}
		var digest = sha.checkSum()
		res = append(buf[:0], digest[:]...)
	}
}

func BenchmarkStdHmacSha256(b *testing.B) {
	var key [16]byte
	var buf [32]byte
	var data = []byte(strings.Repeat("test ", 20))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var h = hmac.New(sha256.New, key[:])
		for i := 0; i < 10; i++ {
			h.Write(data)
		}
		res = h.Sum(buf[:0])
	}
}

func BenchmarkLocHmacSha256(b *testing.B) {
	var key [16]byte
	var buf [32]byte
	var data = []byte(strings.Repeat("test ", 20))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		res = Digest(buf[:0], key[:], data, data, data, data, data, data, data, data, data, data)
	}
}
