# Migrating

This page will document breaking changes between major versions of
`gosso`. There are no prior releases yet, so there is nothing to
migrate from.

When the first breaking change lands, the pattern will be:

```md
## v1 -> v2

### `saml.WithX` renamed to `saml.WithY`

... before / after code examples ...
```

## Unreleased

- **Go 1.27 is the minimum version.** `github.com/foomo/keel/persistence/mongo`
  (used by `oidc/native/mongostore`) requires it.
- No API breaks: login context, `WithOnLoginError`, `RP.Refresh` and the
  `oidc/native` broker are additions. Without a login context or
  `WithOnLoginError`, the web flow behaves exactly as before.
- The destination returned by `OnRedirect` was never sanitised; this is
  now documented as intended (the consumer owns it).

Follow [the release notes on GitHub](https://github.com/foomo/gosso/releases)
for a summary of every release.
