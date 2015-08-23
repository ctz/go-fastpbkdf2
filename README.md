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
$ go test -bench . -benchtime 3s
PASS
Benchmark_fastpbkdf2_SHA1       20   196906583 ns/op
Benchmark_std_SHA1         5   968360473 ns/op
Benchmark_fastpbkdf2_SHA256       10   525602930 ns/op
Benchmark_std_SHA256         2  2816165015 ns/op
Benchmark_fastpbkdf2_SHA512       10   662370439 ns/op
Benchmark_std_SHA512         1  3979382464 ns/op
ok    fastpbkdf2  42.101s
```

So that's around 4.91x, 5.35x and 6.01x faster, for SHA1, SHA256 and SHA512 respectively.

## Building and testing

This uses `cgo` for ffi, and you will need OpenSSL.  `go build` should do the right thing.
`go test` runs the tests.

## License
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
