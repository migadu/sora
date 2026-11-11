//go:build integration

package common

// VacationIdentityCase exercises response identity independently from sender:
// the caller delivers subjects "first" and "second" from the same address.
type VacationIdentityCase struct {
	Name    string
	Script  string
	Replies int
}

func VacationIdentityCases() []VacationIdentityCase {
	return []VacationIdentityCase{
		{"different handles", `require "vacation"; if header :is "subject" "first" { vacation :handle "one" "Away"; } else { vacation :handle "two" "Away"; }`, 2},
		{"same handle different reasons", `require "vacation"; if header :is "subject" "first" { vacation :handle "same" "Away"; } else { vacation :handle "same" "Contact support"; }`, 1},
		{"different implicit reasons", `require "vacation"; if header :is "subject" "first" { vacation "Away"; } else { vacation "Contact support"; }`, 2},
		{"different implicit subjects", `require "vacation"; if header :is "subject" "first" { vacation :subject "One" "Away"; } else { vacation :subject "Two" "Away"; }`, 2},
		{"explicit empty handle", `require "vacation"; if header :is "subject" "first" { vacation :handle "" "Away"; } else { vacation :handle "" "Contact support"; }`, 1},
		{"empty and omitted handles differ", `require "vacation"; if header :is "subject" "first" { vacation :handle "" "Away"; } else { vacation "Away"; }`, 2},
		{"variables do not change implicit identity", `require ["vacation", "variables"]; if header :matches "subject" "*" { vacation :subject "Automatic ${1}" "Away"; }`, 1},
		{"variables do not change explicit identity", `require ["vacation", "variables"]; if header :matches "subject" "*" { vacation :handle "${1}" "Away"; }`, 1},
	}
}
