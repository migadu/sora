package helpers

import (
	"encoding/base64"
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrInvalidModifiedUTF7 indicates the input is not valid Modified UTF-7.
	ErrInvalidModifiedUTF7 = errors.New("utf7: invalid Modified UTF-7")

	// Modified Base64 alphabet: standard Base64 with ',' instead of '/'
	modifiedBase64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,")
	// Without the "=" pad (RFC 2152). Strict makes decoding refuse non-zero discarded
	// bits, which RFC 2152 calls ill-formed; it does not change encoding.
	modifiedBase64Raw = modifiedBase64.WithPadding(base64.NoPadding).Strict()
)

// isModifiedBase64 reports whether c is in the modified BASE64 alphabet.
func isModifiedBase64(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == ','
}

// EncodeModifiedUTF7 encodes a UTF-8 string into Modified UTF-7 (RFC 3501 §5.1.3).
// Printable US-ASCII characters (0x20..0x7E) other than '&' represent themselves,
// '&' is encoded as "&-", and all other runes are encoded as UTF-16BE in unpadded
// Modified Base64 shifted with '&' and '-'.
func EncodeModifiedUTF7(src string) string {
	needsEncoding := false
	for i := 0; i < len(src); i++ {
		if src[i] < 0x20 || src[i] > 0x7e || src[i] == '&' {
			needsEncoding = true
			break
		}
	}
	if !needsEncoding {
		return src
	}

	result := make([]byte, 0, len(src)+8)
	var utf16Buf []byte

	flush := func() {
		if len(utf16Buf) == 0 {
			return
		}
		result = append(result, '&')
		result = modifiedBase64Raw.AppendEncode(result, utf16Buf)
		result = append(result, '-')
		utf16Buf = utf16Buf[:0]
	}

	for i := 0; i < len(src); {
		b := src[i]
		if b >= 0x20 && b <= 0x7e {
			flush()
			if b == '&' {
				result = append(result, '&', '-')
			} else {
				result = append(result, b)
			}
			i++
			continue
		}
		r, width := utf8.DecodeRuneInString(src[i:])
		i += width
		if r <= 0xffff {
			utf16Buf = append(utf16Buf, byte(r>>8), byte(r))
		} else {
			r1, r2 := utf16.EncodeRune(r)
			utf16Buf = append(utf16Buf, byte(r1>>8), byte(r1), byte(r2>>8), byte(r2))
		}
	}
	flush()

	return string(result)
}

// DecodeModifiedUTF7 decodes a Modified UTF-7 encoded string (RFC 3501) to UTF-8.
// If the string contains no Modified UTF-7 sequences (i.e., no '&' characters),
// it is returned as-is. Only the canonical BASE64 form of a name decodes: non-printable
// or 8-bit octets outside a shift, BASE64 that encodes printable US-ASCII, a null
// shift, a byte outside the modified BASE64 alphabet and non-zero discarded bits are
// invalid.
func DecodeModifiedUTF7(src string) (string, error) {
	// Fast path: no '&' means no Modified UTF-7 encoding
	hasAmpersand := false
	for i := 0; i < len(src); i++ {
		if src[i] == '&' {
			hasAmpersand = true
			break
		}
	}
	if !hasAmpersand {
		return src, nil
	}

	result := make([]byte, 0, len(src))
	afterBase64 := false // the previous token was a BASE64 segment

	for i := 0; i < len(src); i++ {
		ch := src[i]

		if ch != '&' {
			// Outside a shift sequence, only printable US-ASCII (0x20..0x7e) may
			// represent itself (RFC 3501 §5.1.3, RFC 9051 §A.1).
			if ch < 0x20 || ch > 0x7e {
				return "", ErrInvalidModifiedUTF7
			}
			result = append(result, ch)
			afterBase64 = false
			continue
		}

		// Find the end of the base64 segment (terminated by '-')
		start := i + 1
		i++
		for i < len(src) && src[i] != '-' {
			// Only the modified BASE64 alphabet is permitted (RFC 9051 §A.1). The
			// base64 package would take '=' and skip CR and LF.
			if !isModifiedBase64(src[i]) {
				return "", ErrInvalidModifiedUTF7
			}
			i++
		}

		if i >= len(src) {
			// Unterminated shift sequence
			return "", ErrInvalidModifiedUTF7
		}

		if start == i {
			// "&-" is the escape sequence for literal '&'
			result = append(result, '&')
			afterBase64 = false
		} else {
			// "-&" while in BASE64 is a null shift (RFC 3501 §5.1.3): both segments
			// belong in one.
			if afterBase64 {
				return "", ErrInvalidModifiedUTF7
			}
			afterBase64 = true

			decoded, err := modifiedBase64Raw.DecodeString(src[start:i])
			if err != nil {
				return "", ErrInvalidModifiedUTF7
			}
			n := len(decoded)

			// Must have even number of bytes (UTF-16-BE)
			if n%2 != 0 {
				return "", ErrInvalidModifiedUTF7
			}

			// Decode UTF-16-BE to UTF-8
			for j := 0; j < n; j += 2 {
				r := rune(decoded[j])<<8 | rune(decoded[j+1])
				if utf16.IsSurrogate(r) {
					if j+2 >= n {
						return "", ErrInvalidModifiedUTF7
					}
					j += 2
					r2 := rune(decoded[j])<<8 | rune(decoded[j+1])
					r = utf16.DecodeRune(r, r2)
					if r == utf8.RuneError {
						return "", ErrInvalidModifiedUTF7
					}
				} else if r >= 0x20 && r <= 0x7e {
					// A printable US-ASCII character has its own form ("&" is "&-"):
					// modified BASE64 MUST NOT represent it (RFC 3501 §5.1.3).
					// Decoding "&AC8-" would make a '/' that adds a hierarchy level.
					return "", ErrInvalidModifiedUTF7
				}
				var buf [4]byte
				w := utf8.EncodeRune(buf[:], r)
				result = append(result, buf[:w]...)
			}
		}
	}

	return string(result), nil
}
