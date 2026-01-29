# Prompt: Hybrid Crawl + Scrape (Rod + net/http)

You are a senior Go engineer working in the Aegis repo. Implement a hybrid crawl+scrape pipeline that:
- Discovers all in-scope links.
- Saves HTML for every page.
- Downloads and saves JS/CSS/images/fonts/media (and referenced assets).
- Detects whether a page is "rendered" (JS-dependent) and chooses the renderer:
  - Rendered => use `github.com/rod/rod`.
  - Not rendered => use `net/http`.
- Captures screenshots.

## Context
Relevant packages:
- `internal/scrape` already crawls + downloads assets (Rod only).
- `internal/crawler` crawls + saves HTML + screenshots (Rod only).
Reuse helpers like `normalizeURL`, `resolveURL`, `parseCSSImports`, `parseJSImport`, and asset download logic.
Keep CLI/configs backward compatible.

## Requirements
1) **Rendered detection**
   - Add `isRendered(html string) (bool, string)` or similar.
   - Use heuristics on raw HTML fetched with `net/http`:
     - Empty/near-empty body or very low text ratio.
     - Presence of SPA shells: `id="root"`, `id="app"`, `data-reactroot`, `__NEXT_DATA__`, `__NUXT__`, `data-v-app`, etc.
     - Large JS bundles + minimal body content.
   - If uncertain, allow a fallback to Rod.
   - Record the decision/reason in logs and manifest.

2) **Static (net/http) path**
   - Fetch HTML via `net/http` (respect timeouts, user-agent, cookies).
   - Save HTML to `pages/...`.
   - Parse HTML to extract links + assets:
     - `a[href]`, `link[href]`, `script[src]`, `img[src|srcset]`,
       `source[src|srcset]`, `iframe/frame`, `object/embed`, `video/audio`.
     - Inline CSS `@import` and `url(...)`.
     - JS imports (`import`, `require`, dynamic import) when reasonable.
   - Download assets using existing download helpers.

3) **Rendered (Rod) path**
   - Navigate, wait for load (and optional network-idle), optional scroll.
   - Save rendered HTML.
   - Extract links/assets from the DOM (same categories as above).
   - Download assets using the same pipeline.

4) **Screenshots**
   - Save screenshots for each page into `screenshots/` under the dump/output dir.
   - For rendered pages: use Rod `PageCaptureScreenshot`.
   - For static pages: either
     - Render once with Rod solely to capture a screenshot, or
     - Explicitly document if screenshots are skipped when `enableScreenshot=false`.
   - Record screenshot paths in the manifest.

5) **Manifest + metadata**
   - Extend manifest/page records to include:
     - renderer: `rod` or `http`
     - renderedDetected: bool
     - screenshotPath (if saved)
   - Keep existing fields and formats (json/yaml).

6) **Limits + safety**
   - Respect `AllowPrivateHosts`, depth, max pages, timeouts, and size limits.
   - Deduplicate visited URLs and downloaded assets.
   - Avoid breaking existing config defaults.

## Implementation Guidance
- Prefer adding logic to `internal/scrape` (it already mirrors assets).
- Optionally reuse the new hybrid scraper from `internal/crawler` to avoid duplication.
- Prefer stdlib parsing (`golang.org/x/net/html`) unless a new dependency is justified.
- Keep helper functions cohesive; avoid copy-paste between crawler/scraper.
- Add clear logs for renderer choice and failures.

## Deliverables
- Code changes implementing hybrid crawl+scrape with renderer detection.
- Updated config structs (if new options are required) and docs.
- Tests for:
  - Rendered detection heuristics.
  - Static page -> net/http path.
  - Rendered page -> Rod path.
  - Asset downloads and screenshot creation.

## Acceptance Criteria
- Static HTML site is crawled and scraped without Rod (except optional screenshot pass).
- SPA/JS-heavy site is crawled with Rod; rendered HTML is saved.
- All link/asset types above are discovered and downloaded.
- Screenshots are saved for crawled pages when enabled.
- Manifest captures renderer decision and screenshot path.
