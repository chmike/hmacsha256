# HMAC-SHA-256 without allocation

HMAC-SHA-256 generates a 32 byte Message Authentication Code (MAC) signed
with a secret key. Unfortunately, the hmac package provides only a stateful
implementation of hmac. That is, every time an hmac must be computed we
must allocate and initialize a new hmac instance which it self allocates
other memory blocks internally.

This package provides an HMAC-SHA-256 implementation that avoids the 
allocations. 

The function `Digest` conputes an HMAC-SHA-256 digest over any number of
data slices given as argument. The digest is appended to the buf slice.

    func Digest(buf []byte, key []byte, data ...[]byte) []byte

When the key is contant, some precomputation can be performed to optimize
the computation of the digest. 

    type Obj struct {
        ... private fields ...
    }

    func (h *HmacSha256) Init(key []byte)

    func (h *HmacSha256) Digest(buf []byte, data ...[]byte) []byte

This current implementation doesn't use hardware available SHA functions.

## Usage examples

Using the `Digest` function.

    import "github.com/chmike/hmacsha256"

    digest := hmacsha256.Digest(nil, key, data1, data2)


Using the Obj structure. 


    import "github.com/chmike/hmacsha256"
     
    var h hmacsha256.Obj
    h.Init(key)

    ...

    digest := h.Digest(buf, data1, data2)

