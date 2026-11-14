package db

import (
	"context"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"
)

// rfc5051Casemap prepares s as RFC 5051 §2 describes: titlecase every code point, then
// decompose fully ("effectively Normalization Form KD"). The prepared strings compare as
// i;octet.
func rfc5051Casemap(s string) string {
	return norm.NFKD.String(strings.Map(unicode.ToTitle, s))
}

// TestSubjectCasemapDigraphs pins upperDigraphs/titleDigraphs to the Unicode tables:
// they must be exactly the code points strings.ToUpper can return whose titlecase is
// another code point, so translating them titlecases a stored subject_sort.
func TestSubjectCasemapDigraphs(t *testing.T) {
	var upper, title []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if u := unicode.ToUpper(r); unicode.ToTitle(u) != u && !strings.ContainsRune(string(upper), u) {
			upper = append(upper, u)
			title = append(title, unicode.ToTitle(u))
		}
	}
	require.Equal(t, upperDigraphs, string(upper))
	require.Equal(t, titleDigraphs, string(title))
}

// TestSortCasemapKeys checks the SQL sort keys against rfc5051Casemap: subjectCasemapKey on
// a subject stored uppercased, addressCasemapKey on a name or address stored lowercased.
func TestSortCasemapKeys(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	sqlKey := func(expr, arg string) string {
		t.Helper()
		var got string
		require.NoError(t, db.GetReadPool().QueryRow(ctx, "SELECT "+expr, arg).Scan(&got))
		return got
	}

	// Letters with a decomposition, ASCII punctuation and digits: right under any LC_CTYPE.
	common := []string{
		"Émile", "Émile", "Ezra", "a_b", "a1@example.com", "a@example.com",
		"Ångström", "naïve façade", "Zoë [x] ^y` {z}", "",
	}
	for _, s := range common {
		want := rfc5051Casemap(s)
		require.Equal(t, want, sqlKey(subjectCasemapKey("$1::text"), strings.ToUpper(s)), "subject %q", s)
		require.Equal(t, want, sqlKey(addressCasemapKey("$1::text"), strings.ToLower(s)), "address %q", s)
	}

	// The subject key needs no case mapping from the database, so it also holds for
	// letters without a decomposition and for RFC 5051's own example, U+01C4.
	for _, s := range []string{"Ǆemal", "ǆemal", "Ljiljana ǉ", "Øystein", "Łukasz", "Ђорђе", "Іван", "Ωμέγα", "ﬁle", "Straße"} {
		require.Equal(t, rfc5051Casemap(s), sqlKey(subjectCasemapKey("$1::text"), strings.ToUpper(s)), "subject %q", s)
	}

	// The address key takes the remaining letters' case from upper(), which follows
	// LC_CTYPE; an ICU or libc UTF-8 locale maps them as titlecase does.
	if sqlKey("upper($1::text)", "ђ") != "Ђ" {
		t.Skip("database LC_CTYPE maps ASCII only")
	}
	for _, s := range []string{"Øystein", "Łukasz", "Ђорђе", "Іван", "Ωμέγα"} {
		require.Equal(t, rfc5051Casemap(s), sqlKey(addressCasemapKey("$1::text"), strings.ToLower(s)), "address %q", s)
	}
}
