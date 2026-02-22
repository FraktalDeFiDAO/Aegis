package scrape

import "testing"

func TestDetectRendered(t *testing.T) {
	cases := []struct {
		name   string
		html   string
		render bool
	}{
		{
			name:   "spa marker",
			html:   `<html><body><div id="root"></div><script src="/app.js"></script></body></html>`,
			render: true,
		},
		{
			name:   "static content",
			html:   `<html><body><h1>Hello</h1><p>World content here.</p></body></html>`,
			render: false,
		},
		{
			name:   "script heavy low text",
			html:   `<html><body><div></div><script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script></body></html>`,
			render: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectRendered(tc.html)
			if got.Rendered != tc.render {
				t.Fatalf("expected rendered=%v got=%v reason=%s", tc.render, got.Rendered, got.Reason)
			}
		})
	}
}

func TestCollectResourcesFromHTML(t *testing.T) {
	baseURL := "https://example.com/path/page"
	html := `
	<html>
	  <head>
		<base href="https://cdn.example.com/base/">
		<link href="/styles/site.css">
		<script src="app.js"></script>
		<style>body{background:url("bg.png")}</style>
	  </head>
	  <body>
		<a href="/about">About</a>
		<img src="img.png" srcset="img2x.png 2x">
		<source srcset="vid1.mp4 1x, vid2.mp4 2x">
		<div style="background:url('/inline.png')"></div>
	  </body>
	</html>`

	links, sources, imports := collectResourcesFromHTML(baseURL, html)

	assertContainsAll(t, links, []string{
		"https://cdn.example.com/about",
	})

	assertContainsAll(t, sources, []string{
		"https://cdn.example.com/styles/site.css",
		"https://cdn.example.com/base/app.js",
		"https://cdn.example.com/base/img.png",
		"https://cdn.example.com/base/img2x.png",
		"https://cdn.example.com/base/vid1.mp4",
		"https://cdn.example.com/base/vid2.mp4",
	})

	assertContainsAll(t, imports, []string{
		"https://cdn.example.com/base/bg.png",
		"https://cdn.example.com/inline.png",
	})
}

func assertContainsAll(t *testing.T, haystack []string, needles []string) {
	t.Helper()
	set := make(map[string]struct{}, len(haystack))
	for _, item := range haystack {
		set[item] = struct{}{}
	}
	for _, needle := range needles {
		if _, ok := set[needle]; !ok {
			t.Fatalf("missing %s in %v", needle, haystack)
		}
	}
}
