package scrape

// Exported helpers for reuse in other packages (e.g. crawler).

func CollectResourcesFromHTML(pageURL string, htmlContent string) ([]string, []string, []string) {
	return collectResourcesFromHTML(pageURL, htmlContent)
}

func ParseCSSImports(content string) []string {
	return parseCSSImports(content)
}

func ParseJSImport(content string) []string {
	return parseJSImport(content)
}

func ParseSrcSet(value string) []string {
	return parseSrcSet(value)
}

func NormalizeURL(raw string) (string, error) {
	return normalizeURL(raw)
}

func ResolveURL(base string, ref string) (string, error) {
	return resolveURL(base, ref)
}

func BuildResourcePath(baseDir string, rawURL string) (string, error) {
	return buildResourcePath(baseDir, rawURL)
}

func IsHTTPURL(raw string) bool {
	return isHTTPURL(raw)
}
