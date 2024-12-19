package server

import (
	"fmt"
	"regexp"
	"strings"
)

const LocalPartRegex = `^(?i)(?:[a-z0-9])+$|^(?:[a-z0-9])(?:[a-z0-9\.\-_])*(?:[a-z0-9])$`
const DomainNameRegex = `^(?i)(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9]|[a-z0-9][a-z0-9\-]+[a-z0-9])+.?$`

type Address struct {
	Address   string
	LocalPart string
	Domain    string
}

func NewAddress(address string) (Address, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	parts := strings.Split(address, "@")
	if len(parts) != 2 {
		return Address{}, fmt.Errorf("unacceptable address: '%s'", address)
	}
	if !regexp.MustCompile(LocalPartRegex).MatchString(parts[0]) {
		return Address{}, fmt.Errorf("unacceptable local part: '%s'", parts[0])
	}
	if !regexp.MustCompile(DomainNameRegex).MatchString(parts[1]) {
		return Address{}, fmt.Errorf("unacceptable domain: '%s'", parts[1])
	}

	return Address{
		Address:   address,
		LocalPart: parts[0],
		Domain:    parts[1],
	}, nil
}
