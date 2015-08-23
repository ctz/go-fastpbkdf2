package fastpbkdf2

/*
#cgo CFLAGS: -std=c99 -O3
#cgo LDFLAGS: -lcrypto
#include "fastpbkdf2.h"
*/
import "C"

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"unsafe"
)

// go doesn't appear to make this easy :(
// we compare hashes of the empty string
func sameHash(a, b func() hash.Hash) bool {
	ha := a().Sum(make([]byte, 0))
	hb := b().Sum(make([]byte, 0))
	return bytes.Equal(ha, hb)
}

func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	output := make([]byte, keyLen)

	if keyLen == 0 {
		return output
	}

	// convert arguments to C types; note that &slice[0] is illegal for empty slices
	var c_password, c_salt, c_output *C.uint8_t
	if len(password) != 0 {
		c_password = (*C.uint8_t)(unsafe.Pointer(&password[0]))
	} else {
		c_password = (*C.uint8_t)(nil)
	}

	if len(salt) != 0 {
		c_salt = (*C.uint8_t)(unsafe.Pointer(&salt[0]))
	} else {
		c_salt = (*C.uint8_t)(nil)
	}

	c_output = (*C.uint8_t)(unsafe.Pointer(&output[0]))

	if sameHash(h, sha1.New) {
		C.fastpbkdf2_hmac_sha1(c_password, C.size_t(len(password)),
			c_salt, C.size_t(len(salt)),
			C.uint32_t(iter),
			c_output, C.size_t(keyLen))
	} else if sameHash(h, sha256.New) {
		C.fastpbkdf2_hmac_sha256(c_password, C.size_t(len(password)),
			c_salt, C.size_t(len(salt)),
			C.uint32_t(iter),
			c_output, C.size_t(keyLen))
	} else if sameHash(h, sha512.New) {
		C.fastpbkdf2_hmac_sha512(c_password, C.size_t(len(password)),
			c_salt, C.size_t(len(salt)),
			C.uint32_t(iter),
			c_output, C.size_t(keyLen))
	} else {
		panic(fmt.Sprintf("Hash function %v not supported (only sha1.New, sha256.New or sha512.New)", h))
	}

	return output
}
