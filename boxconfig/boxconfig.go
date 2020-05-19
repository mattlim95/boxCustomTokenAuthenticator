package boxconfig

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// Box Config file
type BoxAppSettings struct {
	BoxAppSettings struct {
		ClientID     string `json:"clientID"`
		ClientSecret string `json:"clientSecret"`
		AppAuth      struct {
			PublicKeyID string `json:"publicKeyID"`
			PrivateKey  string `json:"privateKey"`
			Passphrase  string `json:"passphrase"`
		} `json:"appAuth"`
	} `json:"boxAppSettings"`
	EnterpriseID string `json:"enterpriseID"`
}

// Box Authentication Response
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

func ReadJSON(location string) (boxAppSettings *BoxAppSettings, err error) {
	// Fetch Json file
	jsonFile, err := os.Open(location)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	// read json as byte array
	byteValue, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(byteValue, &boxAppSettings)

	return boxAppSettings, err
}

// Generate Random modules need to find a new home, putting in boxconfig for now
//Used for generating random ID
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

//Used for generating random ID
func GenerateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}
