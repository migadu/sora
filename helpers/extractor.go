package helpers

import (
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
)

type Recipient struct {
	EmailAddress string `json:"email"`
	AddressType  string `json:"type"`
	Name         string `json:"name,omitempty"`
}

func ExtractRecipients(header message.Header) []Recipient {
	recipients := make([]Recipient, 0)
	uniquePairs := make(map[string]struct{})

	extractAddresses := func(key string) {
		values := header.Values(key)
		for _, value := range values {
			value := SanitizeUTF8(value)
			// TODO: is this the right way to handle the addresses? ParseAddressList says
			// to use Header.AddressList instead
			addresses, err := mail.ParseAddressList(value)
			if err == nil {
				for _, addr := range addresses {
					addressType := strings.ToLower(key)
					uniqueKey := addr.Address + "|" + addressType

					if _, exists := uniquePairs[uniqueKey]; !exists {
						recipient := Recipient{
							EmailAddress: addr.Address,
							AddressType:  addressType,
							Name:         addr.Name,
						}
						recipients = append(recipients, recipient)
						uniquePairs[uniqueKey] = struct{}{}
					}
				}
			}
		}
	}

	extractAddresses("To")
	extractAddresses("Cc")
	extractAddresses("Bcc")
	extractAddresses("From")
	extractAddresses("Sender")
	extractAddresses("Reply-To")

	return recipients
}
