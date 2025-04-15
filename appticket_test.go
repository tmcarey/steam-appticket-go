package steamappticket

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	ticket := "TICKET"
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(ticket))
	decodedTicket, err := io.ReadAll(decoder)
	if err != nil {
		log.Fatal(err)
	}

	key, err := hex.DecodeString("KEY")
	if err != nil {
		log.Fatal(err)
	}

	app_ticket, err := ParseEncryptedAppTicket(decodedTicket, key)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(app_ticket)
}
