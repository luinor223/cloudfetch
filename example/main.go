package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/luinor223/cloudfetch"
)

func main() {
	client := cloudfetch.New()

	resp, err := client.Get("https://tradingeconomics.com/commodities")
	if err != nil {
		log.Fatal(err)
	}

	text, err := resp.Text()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Status:   %d\n", resp.StatusCode)
	fmt.Printf("Length:   %d bytes\n", len(text))
	fmt.Printf("Has data: %v\n", strings.Contains(text, "CL1:COM"))
}
