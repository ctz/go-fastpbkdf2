package fastpbkdf2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

import stdpbkdf2 "golang.org/x/crypto/pbkdf2"

func check(t *testing.T, hash func() hash.Hash, hexPassword, hexSalt string, iterations int, hexAnswer string) {
	password, _ := hex.DecodeString(hexPassword)
	salt, _ := hex.DecodeString(hexSalt)
	answer, _ := hex.DecodeString(hexAnswer)

	value := Key(password, salt, iterations, len(answer), hash)
	if !bytes.Equal(value, answer) {
		t.Errorf("Go answer %v != expected %v", value, answer)
	}
	t.Logf("test passed\n")
}

func TestSHA1(t *testing.T) {
	check(t, sha1.New, "70617373776f7264", "73616c74", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6")
	check(t, sha1.New, "70617373776f7264", "73616c74", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
	check(t, sha1.New, "70617373776f7264", "73616c74", 4096, "4b007901b765489abead49d926f721d065a429c1")
	check(t, sha1.New, "70617373776f7264", "73616c74", 16777216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984")
	check(t, sha1.New, "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 4096, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
	check(t, sha1.New, "7061737300776f7264", "7361006c74", 4096, "56fa6aa75548099dcc37d7f03425e0c3")
}

func TestSHA256(t *testing.T) {
	check(t, sha256.New, "706173737764", "73616c74", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
	check(t, sha256.New, "50617373776f7264", "4e61436c", 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d")
	check(t, sha256.New, "70617373776f7264", "73616c74", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
	check(t, sha256.New, "70617373776f7264", "73616c74", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
	check(t, sha256.New, "70617373776f7264", "73616c74", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
	check(t, sha256.New, "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 4096, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
	check(t, sha256.New, "", "73616c74", 1024, "9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d")
	check(t, sha256.New, "70617373776f7264", "", 1024, "ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46")
	check(t, sha256.New, "7061737300776f7264", "7361006c74", 4096, "89b69d0516f829893c696226650a8687")
}

func TestSHA512(t *testing.T) {
	check(t, sha512.New, "70617373776f7264", "73616c74", 1, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252")
	check(t, sha512.New, "70617373776f7264", "73616c74", 2, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c")
	check(t, sha512.New, "70617373776f7264", "73616c74", 4096, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5")
	check(t, sha512.New, "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", 1, "6e23f27638084b0f7ea1734e0d9841f55dd29ea60a834466f3396bac801fac1eeb63802f03a0b4acd7603e3699c8b74437be83ff01ad7f55dac1ef60f4d56480c35ee68fd52c6936")
}

var benchmarkIterations = 512 * 1024

func Benchmark_fastpbkdf2_SHA1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Key([]byte("password"), []byte("salt"), benchmarkIterations, 20, sha1.New)
	}
}

func Benchmark_std_SHA1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		stdpbkdf2.Key([]byte("password"), []byte("salt"), benchmarkIterations, 20, sha1.New)
	}
}


func Benchmark_fastpbkdf2_SHA256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Key([]byte("password"), []byte("salt"), benchmarkIterations, 32, sha256.New)
	}
}

func Benchmark_std_SHA256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		stdpbkdf2.Key([]byte("password"), []byte("salt"), benchmarkIterations, 32, sha256.New)
	}
}

func Benchmark_fastpbkdf2_SHA512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Key([]byte("password"), []byte("salt"), benchmarkIterations, 64, sha512.New)
	}
}

func Benchmark_std_SHA512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		stdpbkdf2.Key([]byte("password"), []byte("salt"), benchmarkIterations, 64, sha512.New)
	}
}
