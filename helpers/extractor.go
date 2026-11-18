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
			if err != nil {
				// net/mail rejects comments and white space inside an addr-spec
				// (see stripAddressCFWS); retry without them rather than drop the
				// header, which lost the address from SEARCH and the ENVELOPE.
				addresses, err = mail.ParseAddressList(stripAddressCFWS(value))
			}
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

// stripAddressCFWS rewrites an address list net/mail failed to parse into one it can.
// RFC 5322 §3.4.1 builds the local-part and the domain of an addr-spec from dot-atoms,
// and a dot-atom may have CFWS (comments and folding white space) on either side, so
// "<user (comment)@ (comment) example.com>" is the address user@example.com; net/mail
// accepts neither the comments nor the white space there. Every comment becomes a space
// (RFC 5322 §3.2.2: it is white space, nested and with quoted-pairs), and the white space
// after "<" and on either side of "@" and ">" is dropped. Quoted strings and domain
// literals are copied verbatim. It is only a fallback: a list net/mail parses keeps its
// comments, so a trailing comment is still taken as the display name there.
func stripAddressCFWS(value string) string {
	out := make([]byte, 0, len(value))
	trimRight := func() {
		for len(out) > 0 && isAddressWSP(out[len(out)-1]) {
			out = out[:len(out)-1]
		}
	}
	skipSpace := false // directly after "<" or "@"
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch ch {
		case '(':
			for depth := 0; i < len(value); i++ {
				switch value[i] {
				case '\\':
					i++
				case '(':
					depth++
				case ')':
					depth--
				}
				if depth == 0 {
					break
				}
			}
			ch = ' '
		case '"', '[':
			end := byte('"')
			if ch == '[' {
				end = ']'
			}
			start := i
			for i++; i < len(value) && value[i] != end; i++ {
				if value[i] == '\\' {
					i++
				}
			}
			out = append(out, value[start:min(i+1, len(value))]...)
			skipSpace = false
			continue
		case '@', '>':
			trimRight()
		}
		if isAddressWSP(ch) {
			if skipSpace {
				continue
			}
		} else {
			skipSpace = ch == '<' || ch == '@'
		}
		out = append(out, ch)
	}
	return string(out)
}

func isAddressWSP(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}
