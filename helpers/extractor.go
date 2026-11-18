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
							EmailAddress: SanitizeUTF8(addr.Address),
							AddressType:  addressType,
							Name:         SanitizeUTF8(addr.Name),
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

// ExtractEnvelopeRecipients returns the addresses a message is sent to: its To, Cc and
// Bcc header addresses, in that order, each once (compared case-insensitively, the
// spelling first seen is kept). It stands in for the envelope of a delivery that names
// no recipients. ExtractRecipients, for the recipients metadata, also lists From,
// Sender and Reply-To, which are not recipients.
func ExtractEnvelopeRecipients(header message.Header) []string {
	var addresses []string
	seen := make(map[string]struct{})
	for _, r := range ExtractRecipients(header) {
		switch r.AddressType {
		case "to", "cc", "bcc":
		default:
			continue
		}
		key := strings.ToLower(r.EmailAddress)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		addresses = append(addresses, r.EmailAddress)
	}
	return addresses
}
