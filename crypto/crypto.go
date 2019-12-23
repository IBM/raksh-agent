package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
)

// GetCMDecryptionKey fetchs the decryption key required for config map
func GetCMDecryptionKey(vaultEnv []string) (key []byte, nonce []byte, err error) {
	key, err = fetchVaultKey(vaultEnv)
	if err != nil {
		return nil, nil, err
	}

	if len(key) == 0 {
		// TODO - add support for specifying the path for symm_key
		// embedded in initrd via env variables
		key, err = ioutil.ReadFile("/symm_key")
		if err != nil {
			return nil, nil, err
		}
	}

	// TODO - add support for specifying the path for nonce
	// embedded in initrd via env variables
	nonce, err = ioutil.ReadFile("/nonce")
	if err != nil {
		return nil, nil, err
	}

	return key, nonce, nil
}

// DecryptSVMConfig decrypts the config map
func DecryptSVMConfig(data []byte, symmKey []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(symmKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintextBytes, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return plaintextBytes, nil

}
