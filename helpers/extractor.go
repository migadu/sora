package helpers

import (
	stdmime "mime"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
)

// ParseAddressList parses the value of an address header field (From, To, Cc, ...) as
// go-message's mail.ParseAddressList does, encoded-word display names included. net/mail
// rejects obsolete source routes and comments inside an addr-spec, which RFC 5322
// requires receivers to interpret. A failed value is retried without source routes
// (section 4.4 says to ignore them), then without addr-spec CFWS. Use it for every
// address header so search, ENVELOPE, vacation and delivery agree on the addresses.
func ParseAddressList(value string) ([]*mail.Address, error) {
	addresses, _, err := parseAddressListRoutes(value)
	return addresses, err
}

// parseAddressListRoutes is ParseAddressList that also returns the source routes it
// removed, for the ENVELOPE, which reports a route as addr-adl (RFC 9051 §7.5.2) even
// though the route is ignored when the address is interpreted. routes is nil when no
// address has one; otherwise it has an entry per address, the canonical route
// (addressRouteEnd) or "". A route is kept only when it is certain which address it
// belongs to: the value must be a plain run of mailboxes, one per comma-separated
// element, which is how parseAddressGroups passes group members and the runs between
// groups. A flat-parsed value with group syntax keeps its addresses without routes.
func parseAddressListRoutes(value string) (addresses []*mail.Address, routes []string, err error) {
	addresses, err = mail.ParseAddressList(value)
	aligned := false
	if err != nil {
		if normalized, found, ok := stripAddressRoutes(value); normalized != value {
			value, routes, aligned = normalized, found, ok
			addresses, err = mail.ParseAddressList(value)
		}
	}
	if err != nil {
		addresses, err = mail.ParseAddressList(stripAddressCFWS(value))
	}
	if err != nil || !aligned || len(routes) != len(addresses) {
		return addresses, nil, err
	}
	return addresses, routes, nil
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
func ExtractRecipients(header message.Header) []Recipient {
	recipients := make([]Recipient, 0)

	extractAddresses := func(key string) {
		addressType := strings.ToLower(key)
		addAddresses := func(addresses []*mail.Address, routes []string) {
			for i, addr := range addresses {
				recipient := Recipient{
					EmailAddress: SanitizeUTF8(addr.Address),
					AddressType:  addressType,
					Name:         SanitizeUTF8(addr.Name),
				}
				if routes != nil {
					recipient.Route = routes[i]
				}
				recipients = append(recipients, recipient)
			}
		}
		for _, value := range header.Values(key) {
			value := SanitizeUTF8(value)
			if parts, ok := parseAddressGroups(value); ok {
				for _, part := range parts {
					if part.group == "" {
						addAddresses(part.addresses, part.routes)
						continue
					}
					recipients = append(recipients, Recipient{AddressType: addressType, Group: part.group})
					addAddresses(part.addresses, part.routes)
					recipients = append(recipients, Recipient{AddressType: addressType, GroupEnd: true})
				}
				continue
			}
			if addresses, routes, err := parseAddressListRoutes(value); err == nil {
				addAddresses(addresses, routes)
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

// addressListPart is a run of an address-list header value: plain addresses (group ""),
// or one RFC 5322 group, its decoded name and its members (none for an empty group).
type addressListPart struct {
	group     string
	addresses []*mail.Address
	routes    []string // nil, or the source route of each address (parseAddressListRoutes)
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
		addresses, routes, err := parseAddressListRoutes(list)
		if err != nil {
			return false
		}
		parts = append(parts, addressListPart{addresses: addresses, routes: routes})
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
		case '[':
			i = skipDomainLiteral(value, i)
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
				addresses, routes, err := parseAddressListRoutes(members)
				if err != nil {
					return nil, false
				}
				part.addresses, part.routes = addresses, routes
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

// skipDomainLiteral returns the closing ']' of the domain literal opened at i.
// Its colons, as in a bare IPv6 address, are not group delimiters. Quoted-pairs
// cannot close the literal; the address parser still validates its contents.
func skipDomainLiteral(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case ']':
			return j
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
		case '(':
			j = skipComment(s, j)
		case '[':
			j = skipDomainLiteral(s, j)
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

// stripAddressRoutes removes only a syntactically valid obs-route at the start of
// an angle-addr. Colons in display names, comments, local parts and domain literals
// are not route separators. The normal parser still validates the final mailbox.
// routes has the canonical route (addressRouteEnd), or "", of each non-empty
// comma-separated element in order; aligned is false when the value has group syntax
// at its top level, where an element is not one mailbox. Without a route to remove,
// stripped is value itself.
func stripAddressRoutes(value string) (stripped string, routes []string, aligned bool) {
	var out strings.Builder
	start := 0
	aligned = true
	route, nonBlank := "", false
	endElement := func() {
		if nonBlank {
			routes = append(routes, route)
		}
		route, nonBlank = "", false
	}
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case ' ', '\t', '\r', '\n':
		case ',':
			endElement()
		case '(':
			i = skipComment(value, i)
		case '"':
			nonBlank = true
			i = skipQuotedString(value, i)
		case '[':
			nonBlank = true
			i = skipDomainLiteral(value, i)
		case '<':
			nonBlank = true
			if end, canonical, ok := addressRouteEnd(value, i+1); ok {
				out.WriteString(value[start : i+1])
				start, route = end, canonical
				i = skipAngleAddr(value, end-1)
			} else {
				i = skipAngleAddr(value, i)
			}
		case ':', ';':
			aligned = false
		default:
			nonBlank = true
		}
	}
	endElement()
	if start == 0 {
		return value, nil, aligned
	}
	out.WriteString(value[start:])
	return out.String(), routes, aligned
}

// addressRouteEnd recognizes RFC 5322 section 4.4 obs-domain-list ":" and returns
// the first byte of its final addr-spec. Empty route-list entries are permitted,
// but at least one @domain is required and every nonempty hop must be valid.
// route is the at-domain-list as the ENVELOPE reports it in addr-adl (RFC 9051
// section 7.5.2), in Dovecot's form: every hop as "@" domain, joined by ",", with
// comments, white space and empty entries dropped ("@first,@second").
func addressRouteEnd(value string, i int) (end int, route string, ok bool) {
	var hops strings.Builder
	i, ok = addressCFWSEnd(value, i)
	for ok && i < len(value) && value[i] == ',' {
		i, ok = addressCFWSEnd(value, i+1)
	}
	if !ok || i == len(value) || value[i] != '@' {
		return 0, "", false
	}
	for {
		if hops.Len() > 0 {
			hops.WriteByte(',')
		}
		hops.WriteByte('@')
		i, ok = addressRouteDomainEnd(value, i+1, &hops)
		if !ok || i == len(value) {
			return 0, "", false
		}
		if value[i] == ':' {
			return i + 1, hops.String(), true
		}
		if value[i] != ',' {
			return 0, "", false
		}
		for value[i] == ',' {
			i, ok = addressCFWSEnd(value, i+1)
			if !ok || i == len(value) {
				return 0, "", false
			}
		}
		if value[i] == ':' {
			return i + 1, hops.String(), true
		}
		if value[i] != '@' {
			return 0, "", false
		}
	}
}

// addressRouteDomainEnd validates a route hop's domain, including obsolete CFWS
// between its dot-separated atoms and domain literals containing colons, and appends
// it to hops without that CFWS (a domain literal as written, unfolded).
func addressRouteDomainEnd(value string, i int, hops *strings.Builder) (int, bool) {
	i, ok := addressCFWSEnd(value, i)
	if !ok || i == len(value) {
		return 0, false
	}
	if value[i] == '[' {
		hops.WriteByte('[')
		for i++; i < len(value); i++ {
			switch ch := value[i]; ch {
			case ']':
				hops.WriteByte(']')
				return addressCFWSEnd(value, i+1)
			case '\\':
				i++
				if i == len(value) || value[i] == 0 || value[i] == '\r' || value[i] == '\n' {
					return 0, false
				}
				hops.WriteByte('\\')
				hops.WriteByte(value[i])
			case '\r':
				if i+2 >= len(value) || value[i+1] != '\n' || (value[i+2] != ' ' && value[i+2] != '\t') {
					return 0, false
				}
				i++
			case '[', '\n', 0:
				return 0, false
			default:
				if ch > 127 {
					return 0, false
				}
				hops.WriteByte(ch)
			}
		}
		return 0, false
	}
	for {
		start := i
		for i < len(value) && (value[i] >= 'a' && value[i] <= 'z' || value[i] >= 'A' && value[i] <= 'Z' || value[i] >= '0' && value[i] <= '9' || strings.IndexByte("!#$%&'*+-/=?^_`{|}~", value[i]) >= 0) {
			i++
		}
		if start == i {
			return 0, false
		}
		hops.WriteString(value[start:i])
		i, ok = addressCFWSEnd(value, i)
		if !ok || i == len(value) || value[i] != '.' {
			return i, ok
		}
		hops.WriteByte('.')
		i, ok = addressCFWSEnd(value, i+1)
		if !ok {
			return 0, false
		}
	}
}

// addressCFWSEnd validates balanced comments and folding whitespace before an
// obsolete route token. Malformed text must not disappear with a stripped route.
func addressCFWSEnd(value string, i int) (int, bool) {
	depth := 0
	for i < len(value) {
		switch value[i] {
		case ' ', '\t':
			i++
		case '\r':
			if i+2 >= len(value) || value[i+1] != '\n' || (value[i+2] != ' ' && value[i+2] != '\t') {
				return 0, false
			}
			i += 2
		case '(', ')':
			if value[i] == '(' {
				depth++
			} else if depth == 0 {
				return i, true
			} else {
				depth--
			}
			i++
		case '\\':
			if depth == 0 {
				return i, true
			}
			i++
			if i == len(value) || value[i] == 0 || value[i] == '\r' || value[i] == '\n' {
				return 0, false
			}
			i++
		case '\n', 0:
			return 0, false
		default:
			if depth == 0 {
				return i, true
			}
			i++
		}
	}
	return i, depth == 0
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
