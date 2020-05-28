package main

import (
	"boxCustomTokenAuthenticator/boxconfig"
	"boxCustomTokenAuthenticator/boxjwt"
	"boxCustomTokenAuthenticator/jws"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	// Call the 3 different token functions
	jws.BoxClient("config.json")
	fmt.Println("done boxjws")
	boxAppSettings, err := boxconfig.ReadJSON("config.json")
	if err != nil {
		fmt.Errorf("cant read JSON")
	}
	client, err := boxjwt.BetterBoxClient(boxAppSettings)
	fmt.Println(err)

	fmt.Println("done boxjwt")

	resp, err := client.Get("https://api.box.com/2.0/users/me")
	printResponse(resp)
}

func printResponse(response *http.Response) {
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("error printing response")
	}
	bodyString := string(bodyBytes)
	log.Println(bodyString)
}
