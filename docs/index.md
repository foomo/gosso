---
layout: home

hero:
  name: gosso
  text: SAML + OIDC for Go
  tagline: Stateless authentication adapters. You own the session.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/foomo/gosso

features:
  - title: Stateless by design
    details: No session storage, no database, no cookies issued by the library. You decide what to do with the authenticated Subject.
  - title: Two protocols, one contract
    details: SAML and OIDC produce the same Subject[T] type. Reuse your session-creation code across both IdPs.
  - title: Batteries, not magic
    details: Functional options, sensible Azure-AD defaults, PKCE by default, an open-redirect guard. No surprise behaviour.
  - title: Sandbox included
    details: One docker compose up and you're logging in as alice@example.com through a real Keycloak.
---
