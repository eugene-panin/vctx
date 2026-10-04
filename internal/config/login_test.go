package config

import (
	"slices"
	"testing"
)

func TestLoginArgs(t *testing.T) {
	for in, want := range map[string][]string{
		"":                                      nil,
		"-method=userpass username=me":          {"-method=userpass", "username=me"},
		`-method=oidc role="dev team"`:          {"-method=oidc", "role=dev team"},
		"-method=ldap   -path=corp  username=x": {"-method=ldap", "-path=corp", "username=x"},
	} {
		got, err := LoginArgs(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"hvs.CAESIJ", "-method=userpass password=x", "token=hvs.x", "-address=http://evil", `role="open`} {
		if _, err := LoginArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLoginArgsWhitelist(t *testing.T) {
	for in, want := range map[string][]string{
		"-method oidc -path sso":           {"-method=oidc", "-path=sso"},
		"-method=userpass\nusername=me":    {"-method=userpass", "username=me"},
		"--method=ldap username=me role=x": {"-method=ldap", "username=me", "role=x"},
		"-method=kerberos keytab_path=/etc/krb5.keytab krb5conf_path=/etc/krb5.conf": {
			"-method=kerberos", "keytab_path=/etc/krb5.keytab", "krb5conf_path=/etc/krb5.conf",
		},
	} {
		got, err := LoginArgs(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{
		"-no-print=false", "-header=X-Vault-Token=hvs.x", "-mfa=123", "-output-curl-string", "-namespace=other",
		"aws_secret_access_key=x", "security_token=x", "secret_key=x", "username=me -path=sso", "-method",
	} {
		if _, err := LoginArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
