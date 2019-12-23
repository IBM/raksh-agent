package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"
)

func TestDecryptSVMConfig(t *testing.T) {
	testString := "Sample String to Test Symmetric Encryption"

	symmetricKey, err := getBytes(32)
	if err != nil {
		t.Errorf("Error occurred while getting symmetric key: %v", err)
	}
	symmKeyNonce, err := getBytes(12)
	if err != nil {
		t.Errorf("Error occurred while getting nonce: %v", err)
	}

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		t.Errorf("Error occurred while getting cipher: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Errorf("Error occurred while getting GCM: %v", err)
	}

	encryptedString := aesgcm.Seal(nil, symmKeyNonce, []byte(testString), nil)

	decryptedString, err := DecryptSVMConfig(encryptedString, symmetricKey, symmKeyNonce)

	if string(decryptedString) != testString {
		t.Errorf("Invalid decrypted content received, expect %s received %s", string(decryptedString), testString)
	}
}

func getBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
