package native

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func applyOpts(opts ...Option) (*Broker, error) {
	b := &Broker{}
	for _, o := range opts {
		if err := o(b); err != nil {
			return nil, err
		}
	}

	return b, nil
}

func TestOptions(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		opt     Option
		wantErr bool
		check   func(t *testing.T, b *Broker)
	}{
		"code ttl ok":         {opt: WithCodeTTL(time.Second), check: func(t *testing.T, b *Broker) { t.Helper(); assert.Equal(t, time.Second, b.codeTTL) }},
		"code ttl zero":       {opt: WithCodeTTL(0), wantErr: true},
		"code ttl negative":   {opt: WithCodeTTL(-time.Second), wantErr: true},
		"session ttl ok":      {opt: WithSessionTTL(time.Hour), check: func(t *testing.T, b *Broker) { t.Helper(); assert.Equal(t, time.Hour, b.sessionTTL) }},
		"session ttl zero":    {opt: WithSessionTTL(0), wantErr: true},
		"grace zero ok":       {opt: WithRotationGrace(0), check: func(t *testing.T, b *Broker) { t.Helper(); assert.Zero(t, b.rotationGrace) }},
		"grace negative":      {opt: WithRotationGrace(-time.Second), wantErr: true},
		"clock nil":           {opt: WithClock(nil), wantErr: true},
		"error logger nil ok": {opt: WithErrorLogger(nil)},
		"deprecated key ok": {
			opt: WithDeprecatedEncryptionKeys([]byte(strings.Repeat("d", 32)), nil, []byte{}),
			check: func(t *testing.T, b *Broker) {
				t.Helper()
				assert.Len(t, b.deprecatedKeys, 1, "empty entries skipped")
			},
		},
		"deprecated key short": {opt: WithDeprecatedEncryptionKeys([]byte("short")), wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			b, err := applyOpts(tc.opt)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tc.check != nil {
				tc.check(t, b)
			}
		})
	}
}

func TestNew_Defaults(t *testing.T) {
	t.Parallel()

	b, err := New(NewMemoryStore(), validHooks(), testClients(), testKey)
	require.NoError(t, err)
	assert.Equal(t, 60*time.Second, b.codeTTL)
	assert.Equal(t, 90*24*time.Hour, b.sessionTTL)
	assert.Equal(t, 10*time.Second, b.rotationGrace)
}
