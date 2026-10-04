package login

import "testing"

func TestVaultError(t *testing.T) {
	out := "Error looking up token: Error making API request.\n\nURL: GET http://v/v1/auth/token/lookup-self\nCode: 503. Errors:\n\n* Vault is sealed\n"
	if got := vaultError(out); got != "Code: 503. Vault is sealed" {
		t.Errorf("got %q", got)
	}
	nested := "Code: 403. Errors:\n\n* 2 errors occurred:\n\t* permission denied\n\t* invalid token\n"
	if got := vaultError(nested); got != "Code: 403. permission denied" {
		t.Errorf("nested: %q", got)
	}
}
