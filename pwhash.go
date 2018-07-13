package pwhash

// md5crypt is Based on https://svnweb.freebsd.org/base/head/lib/libcrypt/crypt-md5.c?view=markup
import "crypto/md5"
import "strings"
import "fmt"
import "crypto/subtle"

// Verify if given password match hash
// for now only md5 crypt is supported
// __`$1$`__*`{salt}`*__$__*`{checksum}`*
func Verify(password string, hashWithSalt string) (bool, error) {
	chunks := strings.Split(hashWithSalt, "$")
	var computedHash string
	var hash string
	if len(chunks) < 2 {
		return false, fmt.Errorf("Invalid hash")
	}
	switch chunks[1] {
	case "1":
		hash = chunks[3]
		computedHash = string(md5Crypt([]byte(password), []byte(chunks[2])))
	default:
		return false, fmt.Errorf("Unsupported '%s'", chunks[1])
	}
	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(hash)) == 1, nil
}

func md5Crypt(passwd, salt []byte) []byte {
	const (
		itoa64      = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		magicString = "$1$"
	)
	// salt is atmost 8 chars
	if len(salt) > 8 {
		salt = salt[:8]
	}
	m := md5.New()
	m.Write(passwd)
	m.Write([]byte(magicString))
	m.Write(salt)

	m2 := md5.New()
	m2.Write(passwd)
	m2.Write(salt)
	m2.Write(passwd)

	mixin := m2.Sum(nil)

	for i := range passwd {
		m.Write([]byte{mixin[i%16]})
	}
	mixin = mixin[:0]

	for l := len(passwd); l != 0; l >>= 1 {
		if l&1 != 0 {
			m.Write([]byte{0})
		} else {
			m.Write([]byte{passwd[0]})
		}

	}

	final := m.Sum(nil)

	for i := 0; i < 1000; i++ {
		m3 := md5.New()
		if i&1 != 0 {
			m3.Write(passwd)
		} else {
			m3.Write(final)
		}

		if i%3 != 0 {
			m3.Write(salt)
		}

		if i%7 != 0 {
			m3.Write(passwd)
		}

		if i&1 != 0 {
			m3.Write(final)
		} else {
			m3.Write(passwd)
		}

		final = m3.Sum(nil)
	}

	var rearranged [22]byte
	rearrangedIndex := 0

	seq := [][3]int32{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10,
		5}}

	for _, p := range seq {
		a, b, c := p[0], p[1], p[2]

		v := uint32(final[a])<<16 | uint32(final[b])<<8 | uint32(final[c])
		for i := 0; i < 4; i++ {
			rearranged[rearrangedIndex] = itoa64[v&0x3f]
			rearrangedIndex++
			v >>= 6
		}
	}

	v := final[11]
	for i := 0; i < 2; i++ {
		rearranged[rearrangedIndex] = itoa64[v&0x3f]
		rearrangedIndex++
		v >>= 6
	}
	final = final[:0]
	return rearranged[:]
}
