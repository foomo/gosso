package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringSliceClaim(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		in   map[string]any
		key  string
		want []string
	}{
		"missing key":        {in: map[string]any{}, key: "groups", want: nil},
		"[]string":           {in: map[string]any{"groups": []string{"a", "b"}}, key: "groups", want: []string{"a", "b"}},
		"[]any":              {in: map[string]any{"groups": []any{"a", "b", 1}}, key: "groups", want: []string{"a", "b"}},
		"single string":      {in: map[string]any{"groups": "admin"}, key: "groups", want: []string{"admin"}},
		"empty string -> []": {in: map[string]any{"groups": ""}, key: "groups", want: nil},
		"csv string":         {in: map[string]any{"groups": "a,b,c"}, key: "groups", want: []string{"a", "b", "c"}},
		"csv string spaces":  {in: map[string]any{"groups": " a , b ,c"}, key: "groups", want: []string{"a", "b", "c"}},
		"csv empty parts":    {in: map[string]any{"groups": ",,"}, key: "groups", want: nil},
		"csv one part": {
			in:   map[string]any{"groups": ",a,"},
			key:  "groups",
			want: []string{"a"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, stringSliceClaim(tc.in, tc.key))
		})
	}
}

func TestBuildSubject_MergeUserInfo(t *testing.T) {
	t.Parallel()

	// UserInfo overrides / adds fields merged on top of ID token claims.
	// sub must be present (buildSubject rejects an empty ExternalID).
	userInfo := map[string]any{
		"sub":        "u-1",
		"given_name": "Alice-User",
		"email":      "alice@example.com",
		"groups":     []any{"admins"},
	}
	sub, err := buildSubject(
		nil,
		"raw.id.token",
		oauthToken{AccessToken: "at", RefreshToken: "rt"},
		userInfo,
		StandardClaimMap,
	)
	require.NoError(t, err)
	assert.Equal(t, "u-1", sub.ExternalID)
	assert.Equal(t, "alice@example.com", sub.Email)
	assert.Equal(t, "Alice-User", sub.Firstname)
	assert.Equal(t, []string{"admins"}, sub.Groups)
	assert.Equal(t, "at", sub.Raw.AccessToken)
	assert.Equal(t, "rt", sub.Raw.RefreshToken)
	assert.Equal(t, "raw.id.token", sub.Raw.RawIDToken)
	assert.Equal(t, userInfo, sub.Raw.UserInfo)
}

func TestBuildSubject_RequiresExternalID(t *testing.T) {
	t.Parallel()

	_, err := buildSubject(
		nil,
		"raw.id.token",
		oauthToken{},
		map[string]any{"email": "no-sub@example.com"},
		StandardClaimMap,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"sub"`)
}
