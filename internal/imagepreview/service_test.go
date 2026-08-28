package imagepreview

import "testing"

func TestAllowedURLAcceptsPublicHTTPSImage(t *testing.T) {
	const rawURL = "https://storage.googleapis.com/example/image.png"
	parsed, valid := allowedURL(rawURL)
	if !valid || parsed.String() != rawURL {
		t.Fatalf("allowedURL(%q) = (%v, %t)", rawURL, parsed, valid)
	}
}

func TestAllowedURLRejectsMalformedURL(t *testing.T) {
	if _, valid := allowedURL("://not-a-url"); valid {
		t.Fatal("allowedURL() accepted a malformed URL")
	}
}
