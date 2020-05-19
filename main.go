package main

import (
	"boxCustomTokenAuthenticator/jws"
	"fmt"
)

func main() {
	// Call the 3 different token functions
	jws.BoxClient("config.json")

	fmt.Println("done")

}
