# Keystore Studio website

A static site: plain HTML, CSS and JavaScript. No build step, no frameworks, no CDNs, no web fonts,
no cookies and no analytics. Every file the pages load is in this folder.

## Preview locally

```bash
cd website
python3 -m http.server 8000
# open http://localhost:8000/
```

Open it through a server rather than as `file://` so the relative links, `site.webmanifest` and
`404.html` behave as they will when hosted.

## File map

| Path | What it is |
| --- | --- |
| `index.html` | Landing page. Its `<head>` holds the Open Graph/Twitter tags and the JSON-LD `SoftwareApplication` block. |
| `downloads/index.html` | Downloads: OS-aware build card, platform cards (`#windows`, `#macos`, `#linux`), build from source (`#source`), requirements, data folders, release notes. No installer is offered yet. |
| `downloads/Keystore Studio_1.0.0_x64-setup.exe` | The Windows installer, tracked with Git LFS. Published to R2, not with the site (see Hosting). |
| `privacy/index.html` | Privacy page (app and website). |
| `changelog/index.html` | Changelog: one `<article id="v<version>">` per release (categorised entries, known limitations, pull requests), the "Road to 1.0" timeline from the commit history, and "Coming next". |
| `changelog/feed.xml` | Atom feed of releases, linked from the changelog's `<head>`. One `<entry>` per release. |
| `apps/index.html` | More apps: the developer's other Windows apps, VS Code extensions and MCP/CLI packages. |
| `feedback/index.html` | Feedback form. It builds a `mailto:hello@keystore-studio.app` link in the browser and opens the visitor's mail app; there is no backend or form service. |
| `404.html` | Not-found page. Self-contained styles and root-absolute paths, so it renders at any missing path. |
| `og.html` | Development page that is the source of `assets/img/og.png`. Not linked; `noindex`. |
| `assets/css/base.css` | Tokens, type, buttons, nav, footer, reveal utilities. Shared by every page. |
| `assets/css/sections.css`, `assets/js/sections.js` | Landing-page sections. |
| `assets/css/iso.css`, `assets/js/iso.js` | Isometric 3D scenes (`<div class="iso-scene" data-scene="…">`), including `apps`, `changelog` and `feedback` for the pages below. Preview them all on `iso-lab.html`. |
| `assets/css/extra.css`, `assets/js/extra.js` | More apps, Changelog and Feedback pages (layout, scene links, the feedback form's mailto builder). Loaded after `pages.css`/`pages.js`, whose tabs and table of contents they reuse. |
| `assets/img/apps/` | Icons of the developer's other apps, self-hosted so the pages make no third-party requests. |
| `assets/css/pages.css`, `assets/js/pages.js` | Downloads, privacy and 404 pages. |
| `assets/js/site.js` | Theme, nav, reveal on scroll, copy buttons, `:root[data-os]` detection. |
| `assets/img/` | App icon, favicon, social card (`og.png`), app screenshots (`shots/`). |
| `robots.txt`, `sitemap.xml`, `site.webmanifest` | Crawling and install metadata. |
| `assets/js/theme-init.js` | Applies the saved theme before first paint; load it in `<head>` on every page. |
| `wrangler.jsonc`, `.assetsignore`, `_headers`, `_redirects` | Cloudflare hosting config (see Hosting). |

## Publishing an installer

The site currently offers no installer; every platform is "build from source". Installers are meant
to be published to Cloudflare R2 and served from
`https://downloads.keystore-studio.app/v<version>/<file name>`, with the site only linking to them.

1. Build it with `pnpm tauri build --bundles nsis`. Do not publish a Microsoft Store (`-Store`)
   build: it embeds the WebView2 offline installer and is about 290 MB instead of a few MB.
2. Put it in `downloads/` (Git LFS tracks it through `.gitattributes`; add a rule if the file name
   pattern changes). Pushing it to the `website` branch runs
   `.github/workflows/website-installers.yml`, which uploads it to R2 under `v<version>/`, the
   version taken from the file name. `wrangler r2 object put` accepts files up to 300 MiB.
3. Get its size and checksum:
   ```bash
   stat -f %z "downloads/Keystore Studio_<version>_x64-setup.exe"      # macOS (Linux: stat -c %s)
   shasum -a 256 "downloads/Keystore Studio_<version>_x64-setup.exe"
   ```
4. Add the download link, size, checksum and unsigned-installer (SmartScreen) notes back to
   `downloads/index.html`, and update the platform status in `index.html`, the platform scene in
   `assets/js/iso.js`, the changelog and the root `README.md`.

## Hosting

The site is a Cloudflare Worker with static assets only (`wrangler.jsonc`), on
`keystore-studio.app` and `www.keystore-studio.app`.

- **Deploys:** `.github/workflows/website.yml` runs `wrangler deploy` from this folder on every push
  to the `website` branch that touches `website/`. By hand: `cd website && npx wrangler deploy`.
- **Not deployed:** `.assetsignore` keeps out the installers (Workers assets cap files at 25 MiB),
  the dev pages (`iso-lab.html`, `og.html`), this README and the Wrangler config.
- **Headers and redirects:** `_headers` sets a strict CSP (same-origin only, no inline scripts) and
  security headers; `_redirects` adds short URLs such as `/download/windows`. If you add a third-party
  resource, a form backend or analytics, loosen the CSP for exactly that and update the privacy page.
- **One-time Cloudflare setup:**
  1. Enable R2 in the dashboard, create the bucket `keystore-studio-downloads`, and connect the
     custom domain `downloads.keystore-studio.app` to it (Bucket → Settings → Custom Domains).
  2. Create an API token with *Workers Scripts: Edit*, *Workers Routes: Edit* on the
     `keystore-studio.app` zone and *R2: Edit*, and add it with your account ID as the repository
     secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
  3. Run the `website` workflow (Actions → Run workflow). Run `website-installers` once an installer
     is ready to publish.
  4. For feedback mail, route `hello@keystore-studio.app` to your inbox with Cloudflare Email Routing.
- **404:** `404.html` uses root-absolute paths (`/assets/…`, `/downloads/`) because it is served at
  any missing path. Locally it only renders correctly when served from the site root.

## Regenerating the social card

```bash
python3 -m http.server 8000 &
"<path to Chrome>" --headless=new --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1200,630 --screenshot=assets/img/og.png "http://localhost:8000/og.html"
```
