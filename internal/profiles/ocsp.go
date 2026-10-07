package profiles

var OCSPProfile = &Profile{
	Name:      "ocsp",
	UserAgent: "Microsoft-CryptoAPI/6.1",
	Host:      "ocsp.verisign.com",
	URIs: []string{
		"/ocsp/",
		"/ocsp",
		"/pki/ocsp/",
		"/pki/ocsp",
		"/ocsp/status",
		"/ocsp/responder",
		"/cgi-bin/ocsp.cgi",
		"/ocsp/OCSP",
	},
	Headers: map[string]string{
		"Content-Type":    "application/ocsp-request",
		"Accept":          "*/*",
		"Connection":      "keep-alive",
		"Accept-Language": "en-US,en;q=0.9",
	},
	Padding:      true,
	PaddingRange: [2]int{32, 256},
	Jitter:       25,
}
