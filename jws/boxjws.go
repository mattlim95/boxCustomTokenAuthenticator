package jws

import (
	"boxCustomTokenAuthenticator/boxconfig"
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"github.com/youmark/pkcs8"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// Box Constants
const (
	appClientID              = "some id"
	appEncryptedClientSecret = "some secret"
	rootID                   = "0"
	rootURL                  = "https://api.box.com/2.0"
	tokenURL                 = "https://api.box.com/oauth2/token"
	redirectURL              = "some url"
	configPath               = "some path"
	boxType                  = "enterprise" // "user" or "enterprise"
)

// Box Variables
var (
	oauthConfig = &oauth2.Config{
		Scopes: nil,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://app.box.com/api/oauth2/authorize",
			TokenURL: "https://app.box.com/api/oauth2/token",
		},
		ClientID:     appClientID,
		ClientSecret: appEncryptedClientSecret,
		RedirectURL:  redirectURL,
	}
)

var boxAppSettings boxconfig.BoxAppSettings

// Box Auth Response
type TokenDetails struct {
	AccessToken     string `json:"access_token"`
	ExpiresIn       int    `json:"expires_in"`
	IssuedTokenType string `json:"issued_token_type"`
	RefreshToken    string `json:"refresh_token"`
	RestrictedTo    []struct {
		Scope  string `json:"scope"`
		Object struct {
			ID         int    `json:"id"`
			Etag       int    `json:"etag"`
			Type       string `json:"type"`
			SequenceID int    `json:"sequence_id"`
			Name       string `json:"name"`
		} `json:"object"`
	} `json:"restricted_to"`
	TokenType string `json:"token_type"`
}

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

func createQueryParams(boxAppSettings *boxconfig.BoxAppSettings) map[string]string {
	queryParams := map[string]string{
		"client_id":     boxAppSettings.BoxAppSettings.ClientID,
		"client_secret": boxAppSettings.BoxAppSettings.ClientSecret,
	}

	return queryParams
}

func requestToken(claims *jws.ClaimSet, signingHeaders *jws.Header, queryParams map[string]string, privateKey *rsa.PrivateKey, client *http.Client) (err error) {
	payload, err := jws.Encode(signingHeaders, claims, privateKey)
	if err != nil {
		return errors.Wrap(err, "Failed to encode payload")
	}
	req, err := http.NewRequest("POST", claims.Aud, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create new request")
	}
	q := req.URL.Query()
	q.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	q.Add("assertion", payload)
	for key, value := range queryParams {
		q.Add(key, value)
	}
	queryString := q.Encode()

	req, err = http.NewRequest("POST", claims.Aud, bytes.NewBuffer([]byte(queryString)))
	if err != nil {
		return errors.Wrap(err, "Failed to create new request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed making auth request")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	log.Println(bodyString)

	if resp.StatusCode != 200 {
		err = errors.New(resp.Status)
		return errors.Wrap(err, "Failed making auth request")
	}
	defer func() {
		deferedErr := resp.Body.Close()
		if deferedErr != nil {
			err = errors.Wrap(err, "Failed to close resp.Body")
		}
	}()

	result := &TokenDetails{}
	err = json.NewDecoder(strings.NewReader(bodyString)).Decode(result)
	if result.AccessToken == "" && err == nil {
		err = errors.New("No AccessToken in Response")
	}
	if err != nil {
		return errors.Wrap(err, "Failed to get token")
	}

	token := &oauth2.Token{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		RefreshToken: result.RefreshToken,
	}

	expiry := result.ExpiresIn
	if expiry != 0 {
		token.Expiry = time.Now().Add(time.Duration(expiry) * time.Second)
	}

	return err

}

func BoxClient(location string) {
	boxAppSettings, err := boxconfig.ReadJSON(location)
	if err != nil {
		log.Fatalf("Step 1: Failed to configure token: %v", err)
	}
	privateKey, err := decryptPrivateKey(boxAppSettings)
	if err != nil {
		log.Fatalf("Step 2 : Failed to configure token: %v", err)
	}
	claims, err := createJWTClaims(boxAppSettings, boxType)
	if err != nil {
		log.Fatalf("Step 3 : Failed to configure token: %v", err)
	}
	signingHeaders := createHeader(boxAppSettings)
	queryParams := createQueryParams(boxAppSettings)
	client := &http.Client{}

	err = requestToken(claims, signingHeaders, queryParams, privateKey, client)
	if err != nil {
		log.Fatalf("Step 4 : Failed to configure token: %v", err)
	} else {
		fmt.Println("Box connection up")
	}
}
