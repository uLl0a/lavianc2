package profiles

var Office365Profile = &Profile{
	Name: "office365",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	Host: "outlook.office365.com",
	URIs: []string{
		"/ews/exchange.asmx",
		"/owa/service.svc",
		"/Microsoft-Server-ActiveSync",
		"/autodiscover/autodiscover.xml",
	},
	Headers: map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.9",
		"Accept-Encoding":           "gzip, deflate, br",
		"Connection":                "keep-alive",
		"Cache-Control":             "no-cache",
		"Pragma":                    "no-cache",
		"X-Requested-With":          "XMLHttpRequest",
		"X-Client-Info":             "Client=Web;Platform=Win32;OsVer=10.0;",
		"Sec-Fetch-Dest":            "empty",
		"Sec-Fetch-Mode":            "cors",
		"Sec-Fetch-Site":            "same-origin",
		"Upgrade-Insecure-Requests": "1",
		// X-Ms-Client-Request-Id y X-Ms-Client-Session-Id se generan
		// dinámicamente en ApplyHeaders, no aquí.
	},
	Padding:      true,
	PaddingRange: [2]int{16, 128},
	Jitter:       15,
}
