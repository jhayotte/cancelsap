package authentication

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// KeycloakServer defines interface to keycloak for authentication
type KeycloakServer interface {
	GetSSOPublicKey() (*SSOPublicKey, error)
	GetSSOClaim() (*SSOClaim, error)
}
type keycloakServer struct {
	SSOCreds *SSOCredentials
}

// NewKeycloakServer creates instance of Keycloak Server
func NewKeycloakServer(ssoCreds *SSOCredentials) KeycloakServer {
	return &keycloakServer{
		SSOCreds: ssoCreds,
	}
}

// GetSSOPublicKey retrieves Public Key from keycloak to be able to verify token locally
func (k *keycloakServer) GetSSOPublicKey() (*SSOPublicKey, error) {
	reqSSO, _ := http.NewRequest("GET", k.SSOCreds.AuthURL+"/realms/"+k.SSOCreds.Realm+"/protocol/openid-connect/token", http.NoBody)

	tokenSSO := k.SSOCreds.ClientID + ":" + k.SSOCreds.Secret
	t := base64.StdEncoding.EncodeToString([]byte(tokenSSO))

	reqSSO.Header.Add("Authorization", fmt.Sprintf("BASIC %s", t))

	clientSSO := &http.Client{}
	resp, err := clientSSO.Do(reqSSO)
	if err != nil {
		return nil, errors.Wrap(err, "SSO Public Key: cannot reach SSO API")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "SSO Public Key: nothing to read")
	}

	pkey := SSOPublicKey{}
	err = json.Unmarshal(body, &pkey)
	if err != nil {
		return nil, errors.Wrap(err, "SSO Public Key: cannot parse the key")
	}

	return &pkey, nil
}

// GetSSOClaim returns SSO Claim containing token to authenticate
func (k *keycloakServer) GetSSOClaim() (*SSOClaim, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	reqSSO, _ := http.NewRequest("POST", k.SSOCreds.AuthURL+"/realms/"+k.SSOCreds.Realm+"/protocol/openid-connect/token", strings.NewReader(data.Encode()))

	tokenSSO := k.SSOCreds.ClientID + ":" + k.SSOCreds.Secret
	t := base64.StdEncoding.EncodeToString([]byte(tokenSSO))

	reqSSO.Header.Add("Authorization", fmt.Sprintf("BASIC %s", t))
	reqSSO.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	clientSSO := &http.Client{}
	resp, err := clientSSO.Do(reqSSO)
	if err != nil {
		return nil, errors.Wrap(err, "SSO Claim: cannot reach SSO API")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "SSO Claim: nothing to read")
	}
	claim := SSOClaim{}
	err = json.Unmarshal(body, &claim)
	if err != nil {
		return nil, errors.Wrap(err, "SSO: cannot parse the claim")
	}
	return &claim, nil
}
