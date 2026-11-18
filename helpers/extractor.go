package helpers

import (
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/go-imap/mailaddr"
)

// ParseAddressList parses the value of an address header field (From, To, Cc, ...) and
// returns its addresses, the members of its groups included, each with its decoded
// display name. The parsing is go-imap's mailaddr.ParseList, the one parser also behind
// the ENVELOPE of an attached message: besides what net/mail accepts it reads obsolete
// source routes (ignored here, RFC 5322 section 4.4) and comments around the "@" of an
// addr-spec. Use it for every address header so search, ENVELOPE, vacation and delivery
// agree on the addresses.
func ParseAddressList(value string) ([]*mail.Address, error) {
	entries, err := mailaddr.ParseList(value)
	if err != nil {
		return nil, err
	}
	var addresses []*mail.Address
	for _, entry := range entries {
		if entry.IsGroupStart() || entry.IsGroupEnd() {
			continue
		}
		addresses = append(addresses, &mail.Address{Name: entry.Name, Address: entry.Mailbox + "@" + entry.Host})
	}
	return addresses, nil
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
	// Route is the obsolete source route of an address written "<@hop1,@hop2:user@domain>"
	// (RFC 5322 §4.4), in canonical form ("@hop1,@hop2"). Only the ENVELOPE reports it,
	// as addr-adl; it is no part of the address for search, sorting, delivery or replies.
	Route string `json:"route,omitempty"`
}

// IsGroupMarker reports whether r is a group start or end rather than an address.
func (r Recipient) IsGroupMarker() bool {
	return r.Group != "" || r.GroupEnd
}

// ExtractRecipients returns the address headers' lists as written, the source of the
// ENVELOPE (RFC 3501 §7.4.2): an address that repeats, in one group or across groups and
// headers of one type, is listed each time. DistinctAddresses gives each address once.
// Every header value is parsed by mailaddr.ParseList, after the bytes PostgreSQL cannot
// store (invalid UTF-8, NUL) are removed from it; a value that does not parse adds nothing.
func ExtractRecipients(header message.Header) []Recipient {
	recipients := make([]Recipient, 0)

	extractAddresses := func(key string) {
		addressType := strings.ToLower(key)
		for _, value := range header.Values(key) {
			entries, err := mailaddr.ParseList(SanitizeUTF8(value))
			if err != nil {
				continue
			}
			for _, entry := range entries {
				switch {
				case entry.IsGroupStart():
					recipients = append(recipients, Recipient{AddressType: addressType, Group: SanitizeUTF8(entry.Mailbox)})
				case entry.IsGroupEnd():
					recipients = append(recipients, Recipient{AddressType: addressType, GroupEnd: true})
				default:
					recipients = append(recipients, Recipient{
						EmailAddress: SanitizeUTF8(entry.Mailbox + "@" + entry.Host),
						AddressType:  addressType,
						Name:         SanitizeUTF8(entry.Name),
						Route:        entry.Route,
					})
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

// DistinctAddresses returns the addresses of recipients without the group markers, each
// address once per header type (the first occurrence, in order): the recipients of a
// message rather than its headers as written.
func DistinctAddresses(recipients []Recipient) []Recipient {
	seen := make(map[string]struct{}, len(recipients))
	distinct := make([]Recipient, 0, len(recipients))
	for _, r := range recipients {
		if r.IsGroupMarker() {
			continue
		}
		key := r.EmailAddress + "|" + r.AddressType
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			distinct = append(distinct, r)
		}
	}
	return distinct
}

// ExtractEnvelopeRecipients returns the addresses a message is sent to: its To, Cc and
// Bcc header addresses, in that order, each once (compared case-insensitively, the
// spelling first seen is kept). It stands in for the envelope of a delivery that names
// no recipients. ExtractRecipients, for the recipients metadata, also lists From,
// Sender and Reply-To, which are not recipients, and the group markers, which are not
// addresses: a group contributes its members, an empty group nothing.
func ExtractEnvelopeRecipients(header message.Header) []string {
	var addresses []string
	seen := make(map[string]struct{})
	for _, r := range ExtractRecipients(header) {
		if r.IsGroupMarker() {
			continue
		}
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
