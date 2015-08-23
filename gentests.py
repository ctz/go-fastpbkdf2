import sys

sys.path.append('./fastpbkdf2')
import testdata

hashes = dict(
    sha1 = 'sha1.New',
    sha256 = 'sha256.New',
    sha512 = 'sha512.New'
)

for hash, tests in sorted(testdata.tests.items()):
    print 'func Test%s(t *testing.T) {' % hash.upper()
    for t in tests:
        print '\tcheck(t, %s, "%s", "%s", %d, "%s")' % (
                hashes[hash],
                t['password'].encode('hex'),
                t['salt'].encode('hex'),
                t['iterations'],
                t['output'].encode('hex'))
    print '}'
    print
