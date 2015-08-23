# go-fastpbkdf2
This is a go binding for [fastpbkdf2](https://github.com/ctz/fastpbkdf2).

It presents the same interface as [the PBKDF2 in the standard library](https://godoc.org/golang.org/x/crypto/pbkdf2)
but outperforms it by a decent amount.

[![Build Status](https://travis-ci.org/ctz/go-fastpbkdf2.svg)](https://travis-ci.org/ctz/go-fastpbkdf2)

## Interface

```go
func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte
```

See the documentation for [the PBKDF2 you'll find in the standard library](https://godoc.org/golang.org/x/crypto/pbkdf2) for details.

Note that it only supports SHA1, SHA256 and SHA512.  Requesting other hashes
will cause a panic.

## Performance

`go test -bench .` will compare performance.  A typical output is:

```
$ go test -bench . -benchtime 10s
testing: warning: no tests to run
PASS
Benchmark_fastpbkdf2_SHA1      100   202401130 ns/op
Benchmark_std_SHA1        20   980523550 ns/op
Benchmark_fastpbkdf2_SHA256       50   539950307 ns/op
Benchmark_std_SHA256         5  3060094011 ns/op
Benchmark_fastpbkdf2_SHA512       50   689964923 ns/op
Benchmark_std_SHA512         5  4124467480 ns/op
```

So that's around 4.85x, 5.66x and 5.98x faster, respectively.

## Building and testing

This uses `cgo` for ffi, and you will need OpenSSL.  `go build` should do the right thing.
`go test` runs the tests.

## License
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
