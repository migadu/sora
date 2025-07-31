package server

import (
	"fmt"
	"regexp"
	"strings"
)

// RFC 5322 compliant email validation regex
// This allows for more valid email addresses than the previous regex
const LocalPartRegex = `^(?i)(?:[a-z0-9!#$%&'*+/=?^_\{\|\}~-])+(?:\.(?:[a-z0-9!#$%&'*+/=?^_\{\|\}~-])+)*$`
const DomainNameRegex = `^(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`

type Address struct {
	fullAddress string
	localPart   string
	domain      string
	detail      string
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

	// Parse detail part from local part
	localPart := parts[0]
	detail := ""
	if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
		detail = localPart[plusIndex+1:]
	}

	return Address{
		fullAddress: address,
		localPart:   localPart,
		domain:      parts[1],
		detail:      detail,
	}, nil
}

func (a Address) FullAddress() string {
	return a.fullAddress
}

func (a Address) LocalPart() string {
	return a.localPart
}

func (a Address) Domain() string {
	return a.domain
}

func (a Address) Detail() string {
	return a.detail
}

// BaseLocalPart returns the local part without the detail (everything before the "+")
func (a Address) BaseLocalPart() string {
	if plusIndex := strings.Index(a.localPart, "+"); plusIndex != -1 {
		return a.localPart[:plusIndex]
	}
	return a.localPart
}

// BaseAddress returns the address without the detail part (e.g., "user@domain.com" from "user+detail@domain.com")
func (a Address) BaseAddress() string {
	return a.BaseLocalPart() + "@" + a.domain
}
