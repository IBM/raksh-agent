package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"os"

	"github.com/sirupsen/logrus"
)

const (
	svmFile              = "/sys/devices/system/cpu/svm"
	agentName            = "kata-agent"
	scConfigmapKey       = "SC_CONFIGMAP_KEY"
	scImageKey           = "SC_IMAGE_KEY"
	nonceKey             = "SC_NONCE"
	kataGuestSvmDir      = "/run/svmkeys"
	rakshSecretsVMTEEDir = "/run/raksh-secrets"
	configMapKeyFileName = "configMapKey"
	imageKeyFileName     = "imageKey"
	nonceFileName        = "nonce"
)

var agentLog = logrus.WithFields(agentFields)
var agentFields = logrus.Fields{
	"name":   agentName,
	"pid":    os.Getpid(),
	"source": "agent",
}

//Returns true if VM TEE (SEV/PEF/MKTME)
func IsVMTEE() bool {
	if isSVM() == true {
		return true
	}
	//ToDo support for SEV and MKTME
	return false
}

//Get Secrets from VM TEE
func PopulateSecretsForVMTEE() error {

	if isSVM() == true {
		err := populateSecretsForSVM()
		return err
	}
	return nil
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
