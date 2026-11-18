package helpers

import (
	stdmime "mime"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
)

// ParseAddressList parses the value of an address header field (From, To, Cc, ...) as
// go-message's mail.ParseAddressList does, encoded-word display names included. net/mail
// rejects comments and white space inside an addr-spec, which RFC 5322 allows (see
// stripAddressCFWS), so a value it rejects is parsed once more without them rather than
// lost. Use it for every address header of a message, so search, ENVELOPE, vacation and
// delivery agree on the addresses.
func ParseAddressList(value string) ([]*mail.Address, error) {
	addresses, err := mail.ParseAddressList(value)
	if err != nil {
		addresses, err = mail.ParseAddressList(stripAddressCFWS(value))
	}
	return addresses, err
}

// Recipient is one entry of a message's stored address lists (messages.recipients_json),
// in header order per AddressType. An entry is either an address, or an RFC 5322 §3.4
// group boundary, which IMAP ENVELOPE reports as an address of its own (RFC 3501
// §7.4.2): a group start carries the group name in Group, a group end has GroupEnd set,
// and both leave EmailAddress and Name empty. IsGroupMarker tells them apart; code that
// wants only the addresses skips the markers.
type Recipient struct {
	EmailAddress string `json:"email"`
	AddressType  string `json:"type"`
	Name         string `json:"name,omitempty"`
	Group        string `json:"group,omitempty"`
	GroupEnd     bool   `json:"group_end,omitempty"`
}

// IsGroupMarker reports whether r is a group start or end rather than an address.
func (r Recipient) IsGroupMarker() bool {
	return r.Group != "" || r.GroupEnd
}

func ExtractRecipients(header message.Header) []Recipient {
	recipients := make([]Recipient, 0)
	uniquePairs := make(map[string]struct{})

	extractAddresses := func(key string) {
		addressType := strings.ToLower(key)
		addAddresses := func(addresses []*mail.Address) {
			for _, addr := range addresses {
				uniqueKey := addr.Address + "|" + addressType
				if _, exists := uniquePairs[uniqueKey]; !exists {
					recipients = append(recipients, Recipient{
						EmailAddress: SanitizeUTF8(addr.Address),
						AddressType:  addressType,
						Name:         SanitizeUTF8(addr.Name),
					})
					uniquePairs[uniqueKey] = struct{}{}
				}
			}
		}
		for _, value := range header.Values(key) {
			value := SanitizeUTF8(value)
			if parts, ok := parseAddressGroups(value); ok {
				for _, part := range parts {
					if part.group == "" {
						addAddresses(part.addresses)
						continue
					}
					recipients = append(recipients, Recipient{AddressType: addressType, Group: part.group})
					addAddresses(part.addresses)
					recipients = append(recipients, Recipient{AddressType: addressType, GroupEnd: true})
				}
				continue
			}
			if addresses, err := ParseAddressList(value); err == nil {
				addAddresses(addresses)
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

// addressListPart is a run of an address-list header value: plain addresses (group ""),
// or one RFC 5322 group, its decoded name and its members (none for an empty group).
type addressListPart struct {
	group     string
	addresses []*mail.Address
}

// parseAddressGroups parses an address-list header value that holds RFC 5322 §3.4
// groups (display-name ":" [group-list] ";"), keeping each group's name and bounds,
// which mail.ParseAddressList drops: it flattens the members into the list and an empty
// group leaves nothing at all. ok is false for a value without a group, and for one
// that is not well formed (a nested or unterminated group, ";" outside a group, a group
// without a name, a run that does not parse); the caller then parses it flat.
func parseAddressGroups(value string) (parts []addressListPart, ok bool) {
	if strings.IndexByte(value, ':') < 0 {
		return nil, false
	}
	addPlain := func(list string) bool {
		if isBlankAddressList(list) {
			return true
		}
		addresses, err := ParseAddressList(list)
		if err != nil {
			return false
		}
		parts = append(parts, addressListPart{addresses: addresses})
		return true
	}
	segStart, lastComma := 0, -1
	inGroup := false
	groupName := ""
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '"':
			i = skipQuotedString(value, i)
		case '(':
			i = skipComment(value, i)
		case '<':
			i = skipAngleAddr(value, i)
		case ',':
			if !inGroup {
				lastComma = i
			}
		case ':':
			if inGroup {
				return nil, false
			}
			nameStart := segStart
			if lastComma >= segStart {
				if !addPlain(value[segStart:lastComma]) {
					return nil, false
				}
				nameStart = lastComma + 1
			}
			groupName = decodePhrase(value[nameStart:i])
			if groupName == "" {
				return nil, false
			}
			inGroup, segStart = true, i+1
		case ';':
			if !inGroup {
				return nil, false
			}
			part := addressListPart{group: groupName}
			if members := value[segStart:i]; !isBlankAddressList(members) {
				addresses, err := ParseAddressList(members)
				if err != nil {
					return nil, false
				}
				part.addresses = addresses
			}
			parts = append(parts, part)
			inGroup, segStart, lastComma = false, i+1, -1
		}
	}
	if inGroup || !addPlain(value[segStart:]) {
		return nil, false
	}
	return parts, true
}

// skipQuotedString returns the index of the '"' closing the quoted-string opened at i
// (the last index if it is unterminated).
func skipQuotedString(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j
		}
	}
	return len(s) - 1
}

// skipComment returns the index of the ')' closing the (nestable) comment opened at i.
func skipComment(s string, i int) int {
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return j
			}
		}
	}
	return len(s) - 1
}

// skipAngleAddr returns the index of the '>' closing the angle-addr opened at i. Its
// ':' (an obsolete route) and quoted local part are not group syntax.
func skipAngleAddr(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '"':
			j = skipQuotedString(s, j)
		case '>':
			return j
		}
	}
	return len(s) - 1
}

// isBlankAddressList reports whether s holds no address: only whitespace, comments and
// the empty list elements RFC 5322 §4.4 obs-addr-list allows (bare commas).
func isBlankAddressList(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n', ',':
		case '(':
			i = skipComment(s, i)
		default:
			return false
		}
	}
	return true
}

// decodePhrase returns an RFC 5322 phrase (a group's display-name) as text: comments
// dropped, quoted-strings unquoted, runs of whitespace folded to one space and RFC 2047
// encoded-words decoded, as net/mail does for an address's display name.
func decodePhrase(s string) string {
	var words []string
	var word strings.Builder
	flush := func() {
		if word.Len() > 0 {
			words = append(words, word.String())
			word.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case ' ', '\t', '\r', '\n':
			flush()
		case '(':
			flush()
			i = skipComment(s, i)
		case '"':
			end := skipQuotedString(s, i)
			content := s[i+1:]
			if s[end] == '"' && end > i {
				content = s[i+1 : end]
			}
			for j := 0; j < len(content); j++ {
				if content[j] == '\\' && j+1 < len(content) {
					j++
				}
				word.WriteByte(content[j])
			}
			i = end
		default:
			word.WriteByte(c)
		}
	}
	flush()
	phrase := strings.Join(words, " ")
	if decoded, err := (&stdmime.WordDecoder{CharsetReader: message.CharsetReader}).DecodeHeader(phrase); err == nil {
		phrase = decoded
	}
	return SanitizeUTF8(phrase)
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
