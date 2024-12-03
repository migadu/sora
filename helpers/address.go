package helpers

import "strings"

func SplitEmailAddress(email string) (string, string) {
	email = strings.ToLower(email)
	parts := strings.Split(email, "@")
	return parts[0], parts[1]
}
