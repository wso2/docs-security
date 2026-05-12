# docs-security: Theme & Version Upgrade Plan

Migrate `wso2/docs-security` from the 2020-era MkDocs Material 4.x stack to the modernized WSO2 MkDocs Material 9.x stack used by `docs-apim` and `docs-is` (Asgardeo).

---

## 1. Current state (baseline)

**Stack (`en/requirements.txt`):**

```
mkdocs==1.0.4              # released 2018
mkdocs-material==4.5.1     # released Jan 2020 — Material 4.x line
markdown==3.1
pymdown-extensions==6.2
jinja2<3.1.0
Pygments==2.7.4
mkdocs-minify-plugin==0.2.1
mkdocs-markdownextradata-plugin==0.2.5
mkdocs-redirects==1.0.0    (listed twice)
markdown-include==0.5.1
mkdocs-material-extensions==1.0.3
mkdocs-exclude==1.0.2
pathlib==1.0.1
```

**`en/mkdocs.yml` (592 lines):**
- Theme: `material`, `custom_dir: theme/material`, palette `deep-orange` only (no light/dark toggle), single logo, `feature: { tabs: true }` (Material 4.x syntax).
- `plugins:` block is **empty** — no search, no redirects plugin enabled.
- `markdown_extensions:` includes a broken duplicate `pymdownx.emoji` (references `materialx.emoji.twemoji` — that module no longer exists in modern pymdown-extensions and will fail in 9.x).
- `extra_css:`, `extra_javascript:`, `extra:` are all empty.
- Nav: 4 top-level sections (Security Processes, Security Guidelines, Security Reporting, Security Announcements). The announcements section is huge (~405 pages).

**`en/theme/material/` — Material 4.x style:**
- `base.html`, `main.html` (Material 4.x template structure).
- `templates/`: `2-column.html`, `single-column.html`, `swagger.html`, `no-nav.html`.
- `partials/`: `nav.html`, `nav-item.html`, `header.html`, `footer.html`, `tabs.html`, `tabs-item.html`, `toc.html`, `language/en.html`.
- `assets/`: hashed filenames (`application.162298c2.js`, `application.572ca0f0.css`) — bundled Material 4.x assets.
- No `home-page.html`, `404.html`, `versions.html`, `copyright.html`, `report-issues.html`, `community.html` — all of which the modern stack has.

**Content (`en/docs/`):**
- 432 markdown files: 405 announcements, 15 guidelines, 5 processes, 5 reporting.
- Asset types: PDF, ZIP, XLSX, j2 (Jinja templates for attachments), PNG, SVG, CSS, JS.

**CI/CD:** No `.github/workflows/` directory. Deploy is external (likely `security.docs.wso2.com` is built from `main` by an off-repo job).

---

## 2. Target stack (chosen reference: docs-apim, with select borrowings from docs-is)

**Why docs-apim:** It is single-product, single-version (like docs-security), modernized to Material 9.x, has the same custom-theme layout WSO2 standardized on. docs-is adds multi-version/multi-flavor complexity we don't need. docs-integrator (Docusaurus) is a full rewrite — out of scope.

**Target `requirements.txt` (pin to match docs-apim, with one bump to docs-is's `mkdocs==1.6.1`):**

```
jinja2==3.1.6
mkdocs==1.6.1
Pygments==2.15.0
pymdown-extensions==10.3.1
mkdocs-minify-plugin==0.6.2
mkdocs-markdownextradata-plugin==0.2.5
mkdocs-redirects==1.2.0
mkdocs-material==9.1.2
markdown-include==0.8.1
markdown==3.2.1
mkdocs-exclude==1.0.2
mkdocs-glightbox==0.3.4
mkdocs-include-markdown-plugin==6.0.0
```

**Target theme:** copy `docs-apim/en/theme/material/` as the base, swap branding (logo/favicon/colour) to security palette, drop sections we don't use (versions picker, redoc, community/report-issues if not desired for a security site).

**Target features (Material 9.x):**
- Light/dark palette toggle (matches docs-apim/docs-is)
- `navigation.indexes`, `navigation.path`, `navigation.top`, `navigation.footer`, `navigation.instant.progress`
- `content.code.copy`, `content.action.edit`, `content.action.view`, `content.tabs.link`
- `search.suggest`, `search.share`

---

## 3. Gap inventory (what must change)

| Area | Current | Target | Change cost |
|---|---|---|---|
| MkDocs version | 1.0.4 | 1.6.1 | Low (config syntax mostly compatible) |
| Material theme | 4.5.1 | 9.1.2 | **High** — major template overhaul |
| `theme.feature.tabs` syntax | Material 4.x | `features: [navigation.tabs, ...]` (9.x list) | Low |
| Palette | single colour | light/dark `media:` + `scheme:` | Low |
| `pymdownx.emoji` duplicate using `materialx.*` | broken in modern stack | single block, `pymdownx.emoji.to_svg` | Low |
| `markdown.extensions.codehilite` + `highlightjs: true` | old highlighting | `pymdownx.highlight` only | Low |
| Custom theme dir | hashed 4.x assets, `base.html`/`main.html` | new partials/templates from docs-apim | **High** — needs port |
| Plugins | none registered | `search`, `redirects`, `minify`, `glightbox`, `markdownextradata`, `include-markdown` | Medium |
| Redirects | none | `redirects.yml` for any legacy advisory URLs | Low–Medium (depends on what already exists in wild) |
| 404 page | missing | `templates/404.html` (port from docs-apim) | Low |
| Home page | uses `index.md` directly | `templates/home-page.html` template | Medium |
| Edit/view links | not configured | `content.action.edit` + `repo_url`/`edit_uri` already set | Low |
| Versioning | none | none needed (single rolling site) | n/a |
| CI/build | none in repo | optional: add `pr-builder.yml` + link-checker like docs-is | Optional |
| Hooks (`hooks.py`) | none | optional, only if we want feature-flagging of advisories | Optional |
| `nav-behaviors.yml`, `features.json` | none | optional, defer | Optional |

---

## 4. Phased plan

### Phase 0 — Branch and baseline (today)
- Branch: `feature/docs-version-upgrade` ✅ already created off updated `main`.
- Confirm current build still works on old stack (sanity check before changes):
  `cd en && pip install -r requirements.txt && mkdocs build --strict=false`
- Snapshot the rendered site (`en/site/`) for visual diffing later.

### Phase 1 — Dependency & config bump (low risk first)
1. Replace `en/requirements.txt` with the target list (Section 2).
2. Update `en/mkdocs.yml` minimally to be parseable by MkDocs 1.6 + Material 9.x:
   - Replace `feature: { tabs: true }` with `features: [navigation.tabs, navigation.tabs.sticky]` plus the full target features list.
   - Convert `palette` to the light/dark `media:` form.
   - Remove the duplicate `pymdownx.emoji` block; keep one with `emoji_generator: !!python/name:pymdownx.emoji.to_svg`.
   - Remove `highlightjs: true` and `markdown.extensions.codehilite`; keep only `pymdownx.highlight` and `pymdownx.superfences`.
   - Add `strict: false` and `validation: { absolute_links: ignore }` (matches base.yml in docs-is).
3. **Temporarily set `theme.custom_dir` to nothing** so we build against pure Material 9.x. Confirm `mkdocs build` succeeds.
4. Spot-check the rendered site in a browser. Capture issues as a list. Build target should be: pages render, nav works, search works.

**Exit criterion:** `mkdocs serve` runs with no warnings (or only the warnings we explicitly allow), site is browsable on Material 9.x defaults.

### Phase 2 — Port the WSO2 theme
1. Copy `docs-apim/en/theme/material/` → `en/theme/material/` (replacing the old 4.x theme).
2. Replace branding:
   - `theme/material/assets/images/logo.svg`, `logo-for-light.svg`, `favicon.png` — swap with security logo/favicon (the existing `en/theme/material/images/logo.svg` is a starting point).
   - Update `theme/material/partials/header.html` and `footer.html` for "WSO2 Security and Compliance Documentation" copy.
3. Decide which docs-apim templates to keep:
   - **Keep:** `404.html`, `home-page.html`, `no-navbars.html`, `partials/*` (header/footer/nav/copyright).
   - **Drop:** `versions.html` (no multi-version), `redoc.html` (no OpenAPI specs in security docs), `community.html`/`report-issues.html` (or repoint to security@wso2.com / responsible-disclosure URL — discuss with team).
4. Re-enable `theme.custom_dir: theme/material` in `mkdocs.yml`. Build, eyeball, fix.

**Exit criterion:** Site visually matches docs-apim style with security branding. Light/dark toggle works. All 432 markdown files render without errors.

### Phase 3 — Plugins & extras
1. Register plugins in `mkdocs.yml`:
   ```yaml
   plugins:
     - search:
         indexing: full
         separator: '[^\w._-]+'
         ngram_length: 3
     - markdownextradata: {}
     - redirects:
         redirect_maps: {}   # populated from redirects.yml via hooks.py (Phase 5) or inline
     - minify:
         minify_html: true
     - glightbox: {}
     - include-markdown: {}
     - exclude:
         glob: [wip/*]
   ```
2. Add `extra_css` / `extra_javascript` pointing at `assets/css/theme.css`, `assets/js/theme.js` (ported from docs-apim).
3. Add `extra:` block with `social:` links and any `markdownextradata` variables the content uses (grep content for `{{ ... }}` placeholders first).

**Exit criterion:** Search returns results. Code blocks have copy buttons. Edit-this-page link goes to the correct file on GitHub `main`.

### Phase 4 — Content fixups
1. **Inline find-and-fix** content that depended on Material 4.x quirks:
   - `!!! note` admonitions: still supported in 9.x — no change.
   - Tabbed content blocks: 4.x syntax (`???+ tab`) → 9.x `=== "Tab Name"` if any.
   - Image paths: many existing images live in `en/docs/assets/img/...` — verify they still resolve.
2. Run a link checker (`mkdocs-htmlproofer-plugin` or external `lychee`) over the built site. Fix broken internal links.
3. Validate large advisory pages render correctly (sample 10 random files across years 2016–2026).

**Exit criterion:** Clean build (no warnings, or a documented allow-list).

### Phase 5 — Redirects (only if needed)
1. `git log` the past year for any URL changes in nav structure. If file paths have moved, populate `en/redirects.yml`:
   ```yaml
   'old/path.md': '{{SITE_URL}}/new/path/'
   ```
2. Wire it up either inline in `mkdocs.yml` (`plugins.redirects.redirect_maps:`) or via `hooks.py` ported from docs-apim (only worth it if the redirect list grows past ~50 entries).
3. Smoke-test 5–10 known old URLs after deploy.

**Exit criterion:** No 404s for previously published advisory URLs.

### Phase 6 — CI & link checks (optional but recommended)
1. Borrow `pr-builder.yml` and `link-checker.yml` from `docs-is/.github/workflows/`:
   - `pr-builder.yml`: runs `mkdocs build --strict=false` on every PR.
   - `link-checker.yml`: scheduled internal/external link audit.
2. Add `markdownlint.yml` if the team wants style enforcement (already used in docs-is).
3. **Do not** touch the existing external deploy pipeline (`security.docs.wso2.com`) without coordinating with whoever owns it — confirm what triggers it before this branch lands.

**Exit criterion:** PRs to `main` get an automatic build-status check.

### Phase 7 — Cutover
1. Final visual review against the live `security.docs.wso2.com`. Diff page counts, section structures, key advisories.
2. Open PR with a "before/after" screenshot grid in the description.
3. Coordinate merge timing with the team owning the deploy pipeline (in case requirements.txt changes break their build container — pin Python to 3.12 if needed, matching docs-is).
4. Post-merge: monitor for 24h, watch for 404 reports.

---

## 5. Open questions to resolve before Phase 1

1. **Who owns the deploy pipeline for `security.docs.wso2.com`?** We need to confirm their build environment (Python version, whether they have a frozen requirements set) before bumping deps.
2. **Are there external URLs (e.g., advisory pages indexed by search engines or linked from wso2.com) that must keep working?** This determines whether Phase 5 is mandatory or optional.
3. **Is there a brand/visual guideline for the new look?** docs-apim uses `deep-orange`-ish branding via Oxygen UI assets. Security docs currently use `deep-orange` too — likely keep it, but confirm.
4. **Do we want feature flagging of advisories (hooks.py + features.json)?** Probably not for a security site (every advisory should be permanent), but flag it as a "no" to be sure.
5. **Multi-version: confirmed not needed?** docs-security is a rolling site; advisories are dated, not versioned. Assume no.
6. **Reporting partials:** docs-apim has `report-issues.html` and `community.html` — for a security docs site we probably want neither in the sidebar; instead a "Report a security issue" CTA pointing to the responsible-disclosure flow.

---

## 6. Effort estimate

| Phase | Estimate | Risk |
|---|---|---|
| 0 — Branch/baseline | 0.5 day | Low |
| 1 — Dep/config bump | 1 day | Medium (broken pymdownx.emoji, codehilite removal) |
| 2 — Theme port | 2–3 days | Medium (re-branding, template trimming) |
| 3 — Plugins/extras | 1 day | Low |
| 4 — Content fixups | 1–2 days | Medium (432 files; needs random-sample review) |
| 5 — Redirects | 0.5–1 day | Low (only if needed) |
| 6 — CI | 0.5 day | Low |
| 7 — Cutover | 0.5 day | Medium (depends on deploy owner) |
| **Total** | **7–10 working days** | |

---

## 7. Reference repos (for copy-paste anchors during execution)

- **Primary template:** `/tmp/wso2-docs-refs/docs-apim/en/` — single-product Material 9.x layout, closest to our shape.
- **Theme assets fallback:** `/tmp/wso2-docs-refs/docs-is/en/theme/material/` — fuller set of partials/templates, including extra fonts (Gilmer) and Oxygen UI icon library — useful if docs-apim's theme is missing something.
- **CI patterns:** `/tmp/wso2-docs-refs/docs-is/.github/workflows/` — `pr-builder.yml`, `link-checker.yml`, `markdownlint.yml`.
- **Do NOT use:** `/tmp/wso2-docs-refs/docs-integrator/` — Docusaurus, out of scope for this migration.
