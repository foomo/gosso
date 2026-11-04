package safepath_test

import (
	"testing"

	"github.com/foomo/gosso/internal/safepath"
	"github.com/stretchr/testify/assert"
)

func TestTarget(t *testing.T) {
	t.Parallel()

	cases := map[string]struct{ in, want string }{
		"empty":                         {"", "/"},
		"simple path":                   {"/dashboard", "/dashboard"},
		"nested path":                   {"/app/profile/edit", "/app/profile/edit"},
		"absolute https rejected":       {"https://evil.example/", "/"},
		"absolute http rejected":        {"http://evil.example/", "/"},
		"scheme relative rejected":      {"//evil.example/", "/"},
		"no leading slash rejected":     {"dashboard", "/"},
		"javascript rejected":           {"javascript:alert(1)", "/"},
		"data uri rejected":             {"data:text/html,x", "/"},
		"backslash prefix rejected":     {`/\evil.example/`, "/"},
		"backslash in middle rejected":  {`/x\y`, "/"},
		"double backslash rejected":     {`\\evil.example\`, "/"},
		"null byte rejected":            {"/path\x00", "/"},
		"newline rejected":              {"/path\n/x", "/"},
		"carriage return rejected":      {"/path\r/x", "/"},
		"tab rejected":                  {"/path\tx", "/"},
		"dotdot allowed (app concern)":  {"/x/../y", "/x/../y"},
		"query kept":                    {"/checkout?step=payment&origin=checkout", "/checkout?step=payment&origin=checkout"},
		"query kept verbatim":           {"/search?q=a%20b&b=2&a=1", "/search?q=a%20b&b=2&a=1"},
		"fragment dropped":              {"/page?x=1#top", "/page?x=1"},
		"empty query dropped":           {"/page?", "/page"},
		"escaped path kept":             {"/a%2Fb?x=1", "/a%2Fb?x=1"},
		"query with backslash rejected": {`/x?y=\evil`, "/"},
		"query with newline rejected":   {"/x?y=a\nb", "/"},
		"scheme relative with query":    {"//evil.example/?x=1", "/"},
		"encoded double slash rejected": {"/%2F%2Fevil.example/?x=1", "/"},
		"absolute with query rejected":  {"https://evil.example/?x=1", "/"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, safepath.Target(tc.in))
		})
	}
}
