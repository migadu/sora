package config

import (
	"slices"
	"strings"
	"testing"
)

func TestAutocertNameRejectsInvalidHostnames(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// 63 + 1 + 63 + 1 + 63 + 1 + 62 = 254 octets (exceeds 253-octet DNS maximum).
	domain254 := strings.Join([]string{label63, label63, label63, strings.Repeat("b", 62)}, ".")

	invalid := []struct {
		name   string
		domain string
	}{
		{"empty", ""},
		{"single_dot", "."},
		{"double_dot", ".."},
		{"triple_dot", "..."},
		{"single_label", "localhost"},
		{"single_label_trailing_dot", "localhost."},
		{"leading_dot", ".example.com"},
		{"double_leading_dot", "..example.com"},
		{"ideographic_leading_dot", "。example.com"},
		{"empty_middle_label", "mail..example.com"},
		{"ideographic_empty_middle_label", "mail。。example.com"},
		{"double_trailing_dot", "mail.example.com.."},
		{"ideographic_double_trailing_dot", "Mail。Example。com。。"},
		{"path_traversal", "../../victim"},
		{"path_traversal_with_domain", "../outside.example.com"},
		{"slash_in_domain", "outside.example.com/file"},
		{"backslash_in_domain", `a\b.example.com`},
		{"ipv4_loopback", "127.0.0.1"},
		{"ipv4_with_trailing_dot", "192.0.2.10."},
		{"ipv6_bracketed", "[::1]"},
		{"ipv6_bare", "::1"},
		{"all_numeric_tld", "example.123"},
		{"host_port", "mail.example.com:443"},
		{"wildcard", "*.example.com"},
		{"underscore", "_dmarc.example.com"},
		{"leading_hyphen", "-mail.example.com"},
		{"trailing_hyphen", "mail-.example.com"},
		{"leading_space", " mail.example.com"},
		{"trailing_space", "mail.example.com "},
		{"control_nul", "mail\x00.example.com"},
		{"label_64_ascii", strings.Repeat("a", 64) + ".example.com"},
		{"label_over_63_punycode", strings.Repeat("ä", 60) + ".example.com"},
		{"domain_254_octets", domain254},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := AutocertName(tc.domain); err == nil {
				t.Errorf("AutocertName(%q) = %q, nil; want error", tc.domain, got)
			}
		})
	}
}

func TestAutocertNameAcceptsValidHostnames(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253 octets (exact DNS maximum).
	domain253 := strings.Join([]string{label63, label63, label63, strings.Repeat("b", 61)}, ".")

	valid := []struct {
		name   string
		domain string
		want   string
	}{
		{"lowercase_ascii", "mail.example.com", "mail.example.com"},
		{"mixed_case_trailing_dot", "Mail.Example.COM.", "mail.example.com"},
		{"idn_ulabel_trailing_dot", "Bücher.example.com.", "xn--bcher-kva.example.com"},
		{"ideographic_dots", "Mail。Example。com", "mail.example.com"},
		{"ideographic_trailing_dot", "Mail。Example。com。", "mail.example.com"},
		{"numeric_subdomain_label", "123.example.com", "123.example.com"},
		{"hyphenated_label", "mx-01.example-mail.com", "mx-01.example-mail.com"},
		{"punycode_alabel", "XN--BCHER-KVA.Example.COM", "xn--bcher-kva.example.com"},
		{"max_63_octet_label", label63 + ".example.com", label63 + ".example.com"},
		{"max_253_octet_domain", domain253, domain253},
		{"max_253_octet_domain_trailing_dot", domain253 + ".", domain253},
	}

	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AutocertName(tc.domain)
			if err != nil {
				t.Fatalf("AutocertName(%q) unexpected error: %v", tc.domain, err)
			}
			if got != tc.want {
				t.Errorf("AutocertName(%q) = %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

func TestLetsEncryptNormalizeDomainsDropsInvalidHostnames(t *testing.T) {
	cfg := loadLetsEncryptFullConfig(t, `domains = ["127.0.0.1", ".example.com", "mail..example.com", "mail.example.com..", "Mail.Example.com"]
default_domain = "127.0.0.1"
[[server]]
type = "imap"
name = "imap"
addr = ":993"
tls = true
tls_default_domain = "mail..example.com"
`)

	want := []string{"mail.example.com"}
	if !slices.Equal(cfg.TLS.LetsEncrypt.Domains, want) {
		t.Errorf("domains = %q, want %q", cfg.TLS.LetsEncrypt.Domains, want)
	}
	if cfg.TLS.LetsEncrypt.DefaultDomain != "" {
		t.Errorf("default_domain = %q, want empty", cfg.TLS.LetsEncrypt.DefaultDomain)
	}
	if cfg.DynamicServers[0].TLSDefaultDomain != "" {
		t.Errorf("tls_default_domain = %q, want empty", cfg.DynamicServers[0].TLSDefaultDomain)
	}
}
