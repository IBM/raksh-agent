package crypto

import "testing"

func TestGatherVaultInfo(t *testing.T) {
	vaultEnv := []string{ScVaultAddress + "=http://localhost:8200",
		ScVaultToken + "=abcedf", ScVaultSecret + "=secret", ScVaultSymmKey + "=keyname"}

	vaultEnvKeys, err := gatherVaultInfo(vaultEnv)
	if err != nil {
		t.Errorf("error getting vault environment variables %+v", err)
	}

	if len(vaultEnvKeys) < 4 {
		t.Errorf("insufficient number of vault environment variables")
	}

	_, a := vaultEnvKeys[ScVaultAddress]
	_, b := vaultEnvKeys[ScVaultToken]
	_, c := vaultEnvKeys[ScVaultSecret]
	_, d := vaultEnvKeys[ScVaultSymmKey]

	if !a || !b || !c || !d {
		t.Errorf("Missing vault environment variables")
	}

	ve2 := vaultEnv[:3]
	vaultEnvKeys, err = gatherVaultInfo(ve2)
	if err == nil {
		t.Errorf("Expected error missing for insufficient vault environment variables")
	}

	vaultEnv = append(vaultEnv, "ABC=123")

	vaultEnvKeys, _ = gatherVaultInfo(vaultEnv)
	if len(vaultEnvKeys) > 4 {
		t.Errorf("Incorrect number of vault environment variables")
	}
}

func TestFetchVaultKey(t *testing.T) {
	vaultEnv := []string{}
	key, err := fetchVaultKey(vaultEnv)
	if err != nil && key != nil {
		t.Errorf("Unexpected error and key values returned")
	}

	vaultEnv = append(vaultEnv, ScVaultAddress+"=http://localhost:8200")
	key, err = fetchVaultKey(vaultEnv)
	if key != nil && err == nil {
		t.Errorf("Unexpected error and key for partial vault environment variables")
	}
}
