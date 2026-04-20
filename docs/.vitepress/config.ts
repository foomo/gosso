import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'gosso',
  description: 'Generic SAML and OIDC adapters for Go',
  base: '/gosso/',
  cleanUrls: true,
  markdown: {
    lineNumbers: true,
  },
  ignoreDeadLinks: [
    /^http:\/\/localhost/,
  ],
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Reference', link: '/reference/configuration' },
      { text: 'godoc', link: 'https://pkg.go.dev/github.com/foomo/gosso' },
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Guide',
          items: [
            { text: 'Getting started', link: '/guide/getting-started' },
            { text: 'Architecture', link: '/guide/architecture' },
            { text: 'SAML', link: '/guide/saml' },
            { text: 'OIDC', link: '/guide/oidc' },
            { text: 'Sandbox', link: '/guide/sandbox' },
            { text: 'Migrating', link: '/guide/migrating' },
          ],
        },
        {
          text: 'Integrations',
          items: [
            { text: 'SAML — Microsoft Entra ID', link: '/guide/integrations/saml-azure-ad' },
            { text: 'OIDC — Custom provider', link: '/guide/integrations/oidc-custom-provider' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Configuration', link: '/reference/configuration' },
            { text: 'API', link: '/reference/api' },
          ],
        },
      ],
      '/': [
        {
          text: 'Contributing',
          items: [
            { text: 'Contributing', link: '/CONTRIBUTING' },
            { text: 'Code of Conduct', link: '/CODE_OF_CONDUCT' },
            { text: 'Security', link: '/SECURITY' },
          ],
        },
      ],
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/foomo/gosso' },
    ],
    editLink: {
      pattern: 'https://github.com/foomo/gosso/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Made with ♥ by foomo / bestbytes',
    },
  },
})
