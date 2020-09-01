package gibberishaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
)

const (
	SaltSize = 8
	Nr       = 14
	Nk       = 8
)

type Cipher struct{}

func (c *Cipher) Dec(source []byte, password []byte) ([]byte, error) {
	cryptArr := make([]byte, base64.StdEncoding.DecodedLen(len(source)))
	base64.StdEncoding.Decode(cryptArr, source)

	salt := cryptArr[8 : 8+SaltSize]
	pbe := c.GetOpenSSLKey(password, salt)
	cryptArr = cryptArr[8+SaltSize:]

	block, err := aes.NewCipher(pbe.Key)
	if err != nil {
		return []byte{}, err
	}

	var decryptedArr []byte = make([]byte, len(cryptArr))

	mode := cipher.NewCBCDecrypter(block, pbe.Iv)
	mode.CryptBlocks(decryptedArr, cryptArr)

	return decryptedArr, nil
}

func (c *Cipher) DecString(source string, password string) (string, error) {
	sourceArr := []byte(source)
	passwordArr := []byte(password)

	decodedArr, err := c.Dec(sourceArr, passwordArr)
	return string(decodedArr), err
}

func (c *Cipher) Enc(source []byte, password []byte) ([]byte, error) {
	salt := RandomArray(SaltSize)
	pbe := c.GetOpenSSLKey(password, salt)
	saltBlock := append([]byte("Salted__"), salt...)

	source = c.AddCBCOpenSSLPadding(source)

	block, err := aes.NewCipher(pbe.Key)
	if err != nil {
		return []byte{}, err
	}

	var cryptArr []byte = make([]byte, len(source))
	mode := cipher.NewCBCEncrypter(block, pbe.Iv)
	mode.CryptBlocks(cryptArr, source)
	cryptArr = append(saltBlock, cryptArr...)

	var base64CryptArr []byte = make([]byte, base64.RawStdEncoding.EncodedLen(len(cryptArr)))
	base64.RawStdEncoding.Encode(base64CryptArr, cryptArr)
	return base64CryptArr, nil
}

func (c *Cipher) EncString(source string, password string) (string, error) {
	sourceArr := []byte(source)
	passwordArr := []byte(password)

	encodedArr, err := c.Enc(sourceArr, passwordArr)
	return string(encodedArr), err
}

func (c *Cipher) GetOpenSSLKey(passwordArr []byte, saltArr []byte) OpenSSLKey {
	rounds := 2
	if Nr >= 12 {
		rounds = 3
	}
	var md5Hash [][16]byte
	data00 := append(passwordArr, saltArr...)
	md5Hash = append(md5Hash, md5.Sum(data00))
	var result []byte
	result = md5Hash[0][:]
	for i := 1; i < rounds; i++ {
		md5Hash = append(md5Hash, md5.Sum(append(md5Hash[i-1][:], data00...)))
		result = append(result, md5Hash[i][:]...)
	}

	key := result[:4*Nk]
	iv := result[4*Nk : 4*Nk+16]
	return OpenSSLKey{
		Key: key,
		Iv:  iv,
	}
}

func (c *Cipher) AddCBCOpenSSLPadding(source []byte) []byte {
	dataOutsideBlocks := len(source) % aes.BlockSize
	if dataOutsideBlocks != 0 {
		dataToAdd := aes.BlockSize - dataOutsideBlocks
		dataToAddByte := byte(dataToAdd)
		for i := 0; i < dataToAdd; i++ {
			source = append(source, dataToAddByte)
		}
	}
	if len(source) == 16 {
		source = append(source, EmptyPaddingBlock...)
	}

	return source
}

func New() *Cipher {
	return &Cipher{}
}
