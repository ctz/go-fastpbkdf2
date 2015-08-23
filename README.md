# go-fastpbkdf2
This is a go binding for [fastpbkdf2](https://github.com/ctz/fastpbkdf2).

It presents the same interface as [golang.org/x/crypto/pbkdf2](https://godoc.org/golang.org/x/crypto/pbkdf2)
but outperforms it by a decent amount.

Note that it only supports SHA1, SHA256 and SHA512.  Requesting other hashes
will cause a panic.

[![Build Status](https://travis-ci.org/ctz/go-fastpbkdf2.svg)](https://travis-ci.org/ctz/go-fastpbkdf2)

## Interface

```go
func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte
```

TODO

## Performance

TODO

## Building and testing

TODO

## License
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
