package profiles

var JQueryProfile = &Profile{
	Name: "jquery",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	Host: "code.jquery.com",
	URIs: []string{
		"/jquery-3.7.1.min.js",
		"/jquery-3.7.1.js",
		"/jquery-3.6.4.min.js",
		"/jquery-3.6.4.js",
		"/jquery-3.5.1.min.js",
		"/libs/jquery/3.7.1/jquery.min.js",
		"/libs/jquery/3.6.4/jquery.min.js",
		"/ajax/libs/jquery/3.5.1/jquery.min.js",
	},
	Headers: map[string]string{
		"Accept":                    "*/*",
		"Accept-Language":           "en-US,en;q=0.9",
		"Accept-Encoding":           "gzip, deflate, br",
		"Connection":                "keep-alive",
		"Cache-Control":             "no-cache",
		"Pragma":                    "no-cache",
		"Sec-Fetch-Dest":            "script",
		"Sec-Fetch-Mode":            "no-cors",
		"Sec-Fetch-Site":            "cross-site",
		"Upgrade-Insecure-Requests": "1",
		// Headers de cacheo condicional (se generan dinámicamente en ApplyHeaders).
		// If-None-Match: se genera con un ETag simulado.
		// If-Modified-Since: se genera con una fecha pasada.
	},
	Padding:      true,
	PaddingRange: [2]int{16, 128},
	Jitter:       20,
}
