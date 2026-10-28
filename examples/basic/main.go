// Command basic fetches a page through cloudfetch and prints its status and
// size.
//
//	go run ./examples/basic https://example.com
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/luinor223/cloudfetch"
)

func main() {
	url := "https://example.com"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}

	client := cloudfetch.New()
	resp, err := client.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	text, err := resp.Text()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Length: %d bytes\n", len(text))
}
