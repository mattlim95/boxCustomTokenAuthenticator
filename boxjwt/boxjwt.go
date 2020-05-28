package boxjwt

import (
	"boxCustomTokenAuthenticator/boxconfig"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"github.com/youmark/pkcs8"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/jws"
	"net/http"
	"net/url"
	"time"
)

const (
	tokenURL = "https://api.box.com/oauth2/token"
	boxType  = "enterprise" // "user" or "enterprise"
)

func decryptPrivateKey(boxAppSettings *boxconfig.BoxAppSettings) (key *rsa.PrivateKey, err error) {

	// Learn how this works

	block, rest := pem.Decode([]byte(boxAppSettings.BoxAppSettings.AppAuth.PrivateKey))
	if len(rest) > 0 {
		return nil, errors.Wrap(err, "box: extra data included in private key")
	}

	rsaKey, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(boxAppSettings.BoxAppSettings.AppAuth.Passphrase))
	if err != nil {
		return nil, errors.Wrap(err, "box: failed to decrypt private key")
	}

	return rsaKey.(*rsa.PrivateKey), nil
}

func createJWTClaims(boxAppSettings *boxconfig.BoxAppSettings, boxSubType string) (claims *jws.ClaimSet, err error) {
	val, err := boxconfig.GenerateRandomString(32)

	claims = &jws.ClaimSet{
		Iss: boxAppSettings.BoxAppSettings.ClientID,
		// Scope:         "",
		Aud: tokenURL,
		Exp: time.Now().Add(time.Second * 45).Unix(),
		Iat: time.Now().Unix(),
		// Typ:           "",
		Sub: boxAppSettings.EnterpriseID,
		Prn: "",
		PrivateClaims: map[string]interface{}{
			"box_sub_type": boxSubType,
			"aud":          tokenURL,
			"jti":          val,
		},
	}

	return claims, nil
}

func createHeader(boxAppSettings *boxconfig.BoxAppSettings) *jws.Header {

	signingHeaders := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     boxAppSettings.BoxAppSettings.AppAuth.PublicKeyID,
	}

	return signingHeaders
}

// Assume passing in box app settings from config json
func BetterBoxClient(boxAppSettings *boxconfig.BoxAppSettings) (*http.Client, error) {
	// Get endpoint params
	privateKey, err := decryptPrivateKey(boxAppSettings)
	if err != nil {
		// log.Fatalf("Step 2 : Failed to configure token: %v", err)
		return nil, fmt.Errorf("step 2 : failed to configure token: %v", err)
	}
	claims, err := createJWTClaims(boxAppSettings, boxType)
	if err != nil {
		// log.Fatalf("Step 3 : Failed to configure token: %v", err)
		return nil, fmt.Errorf("step 3 : failed to configure token: %v", err)
	}
	signingHeaders := createHeader(boxAppSettings)
	// queryParams := createQueryParams(boxAppSettings)

	// Assemble payload params
	payload, err := jws.Encode(signingHeaders, claims, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to encode payload")
	}

	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	v.Add("assertion", payload)

	config := &clientcredentials.Config{
		ClientID:       boxAppSettings.BoxAppSettings.ClientID,
		ClientSecret:   boxAppSettings.BoxAppSettings.ClientSecret,
		TokenURL:       tokenURL,
		Scopes:         nil,
		EndpointParams: v,
		AuthStyle:      1,
	}

	client := config.Client(oauth2.NoContext)

	return client, err
}
