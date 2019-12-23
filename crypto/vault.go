package crypto

import (
	"fmt"
	"strings"

	b64 "encoding/base64"

	vaultApi "github.com/hashicorp/vault/api"
)

const (
	// ScVaultAddress is the address of the vault server
	ScVaultAddress = "SC_VAULT_ADDR"

	// ScVaultToken is the token used for authentication with the vault server
	ScVaultToken = "SC_VAULT_TOKEN"

	// ScVaultSecret is name of the secret resource on the vault server
	ScVaultSecret = "SC_VAULT_SECRET"

	// ScVaultSymmKey is name of the key stored in vault server resource
	ScVaultSymmKey = "SC_VAULT_SYMM_KEY"
)

func gatherVaultInfo(vaultEnv []string) (map[string]string, error) {
	vaultEnvKeys := make(map[string]string)
	vaultInfoMap := make(map[string]struct{})

	for _, vaultVar := range []string{ScVaultAddress, ScVaultToken, ScVaultSecret, ScVaultSymmKey} {
		vaultInfoMap[vaultVar] = struct{}{}
	}

	for _, envVal := range vaultEnv {
		s := strings.SplitN(envVal, "=", 2)
		if len(s) > 1 {
			_, ok := vaultInfoMap[s[0]]
			if ok {
				// TODO - this vault related env variables should be purged
				// before container execution starts
				vaultEnvKeys[s[0]] = s[1]
			}
		}
	}

	if len(vaultEnvKeys) > 0 && len(vaultEnvKeys) < 4 {
		return nil, fmt.Errorf("Pleaes specify %s %s %s and %s env variables in the pod spec", ScVaultAddress, ScVaultToken, ScVaultSecret, ScVaultSymmKey)
	}

	return vaultEnvKeys, nil
}

func fetchVaultKey(vaultEnv []string) ([]byte, error) {
	vaultEnvKeys, err := gatherVaultInfo(vaultEnv)
	if err != nil {
		return nil, err
	}
	if err == nil && len(vaultEnvKeys) == 0 {
		return nil, nil
	}

	config := &vaultApi.Config{
		Address: vaultEnvKeys[ScVaultAddress],
	}
	client, err := vaultApi.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(vaultEnvKeys[ScVaultToken])
	c := client.Logical()
	secret, err := c.Read(vaultEnvKeys[ScVaultSecret])
	if err != nil {
		return nil, err
	}

	vaultData := secret.Data["data"].(map[string]interface{})
	key, err := b64.StdEncoding.DecodeString(fmt.Sprintf("%s", vaultData[vaultEnvKeys[ScVaultSymmKey]]))

	return key, err
}
