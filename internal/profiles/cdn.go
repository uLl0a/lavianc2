package profiles

var CDNProfile = &Profile{
	Name: "cdn",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	Host: "cdn.cloudflare.com",
	URIs: []string{
		"/cdn-cgi/beacon/expect-ct",
		"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1",
		"/cdn-cgi/l/email-protection",
		"/cdn-cgi/trace",
		"/cdn-cgi/speculation",
		"/assets/js/app.min.js",
		"/assets/css/main.min.css",
		"/static/fonts/inter.woff2",
		"/static/img/logo.svg",
	},
	Headers: map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.9",
		"Accept-Encoding":           "gzip, deflate, br",
		"Connection":                "keep-alive",
		"Cache-Control":             "no-cache",
		"Pragma":                    "no-cache",
		"Sec-Fetch-Dest":            "empty",
		"Sec-Fetch-Mode":            "cors",
		"Sec-Fetch-Site":            "same-origin",
		"Upgrade-Insecure-Requests": "1",
		// Headers dinámicos de Cloudflare (se generan en ApplyHeaders).
		// No los definimos aquí porque cambian por request.
		// "CF-Ray":          se genera dinámicamente
		// "CF-Connecting-IP": se genera dinámicamente (opcional)
		// "CF-IPCountry":    se genera dinámicamente (opcional)
		// "CDN-Loop":        se genera dinámicamente (opcional)
	},
	Padding:      true,
	PaddingRange: [2]int{32, 256}, // CDNs devuelven assets de tamaños muy variados
	Jitter:       20,              // 20% de jitter (más agresivo que Office365)
}
