package gibberishaes

import (
	"math/rand"
	"time"
)

// Version specifies the GibberishAES version being used.
const Version = "0.0.0"

var EmptyPaddingBlock = []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func RandomArray(num int) []byte {
	result := make([]byte, num)
	rand.Read(result)
	return result
}

type OpenSSLKey struct {
	Key []byte
	Iv  []byte
}
