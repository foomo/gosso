package sso_test

import (
	"testing"

	sso "github.com/foomo/gosso"
	"github.com/stretchr/testify/assert"
)

type role string

const (
	roleAdmin role = "admin"
	roleUser  role = "user"
)

func TestGroupMapper(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mapper sso.GroupMapper[role]
		input  []string
		want   []role
	}{
		"empty mapper": {
			mapper: sso.GroupMapper[role]{},
			input:  []string{"a", "b"},
			want:   nil,
		},
		"empty input": {
			mapper: sso.GroupMapper[role]{"a": roleAdmin},
			input:  nil,
			want:   nil,
		},
		"translates known groups": {
			mapper: sso.GroupMapper[role]{
				"ad-admins": roleAdmin,
				"ad-users":  roleUser,
			},
			input: []string{"ad-admins", "ad-users"},
			want:  []role{roleAdmin, roleUser},
		},
		"skips unknown groups": {
			mapper: sso.GroupMapper[role]{"ad-admins": roleAdmin},
			input:  []string{"noise", "ad-admins", "other"},
			want:   []role{roleAdmin},
		},
		"deduplicates when multiple groups map to same role": {
			mapper: sso.GroupMapper[role]{
				"ad-admins-eu": roleAdmin,
				"ad-admins-us": roleAdmin,
			},
			input: []string{"ad-admins-eu", "ad-admins-us"},
			want:  []role{roleAdmin},
		},
		"preserves first-seen order": {
			mapper: sso.GroupMapper[role]{
				"g1": roleUser,
				"g2": roleAdmin,
			},
			input: []string{"g2", "g1"},
			want:  []role{roleAdmin, roleUser},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tc.mapper.Map(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
