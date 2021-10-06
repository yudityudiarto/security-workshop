package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func DecryptAES(key, input string) ([]byte, error) {
	keyByte, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()

	if len(data) < gcm.NonceSize() {
		return nil, err
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func DecryptRSA(recipient, input string) (result []byte, err error) {
	switch recipient {
	case ServiceA:
		err = SetPublicKeyAndPrivateKeyServiceA()
	case ServiceB:
		err = SetPublicKeyAndPrivateKeyServiceB()
	}

	if err != nil {
		return result, err
	}

	msgByte, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, msgByte, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
