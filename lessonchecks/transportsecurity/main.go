package main

import (
	"crypto/tls"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/config"
	"github.com/bootdotdev/learn-web-security/internal/httpserver"
	"github.com/bootdotdev/learn-web-security/internal/logging"
)

const (
	hstsValue        = "max-age=31536000; includeSubDomains"
	productionOrigin = "https://bearly-secure.example"
)

type result struct {
	EnvironmentDocumented           bool `json:"environmentDocumented"`
	ConfiguredHopCountExact         bool `json:"configuredHopCountExact"`
	NegativeHopCountRejected        bool `json:"negativeHopCountRejected"`
	ServerWiringConfigured          bool `json:"serverWiringConfigured"`
	LocalHTTPPreserved              bool `json:"localHTTPPreserved"`
	InsecureProductionRedirected    bool `json:"insecureProductionRedirected"`
	DirectHTTPSAccepted             bool `json:"directHTTPSAccepted"`
	TrustedForwardedHTTPSAccepted   bool `json:"trustedForwardedHTTPSAccepted"`
	UntrustedForwardedHTTPSRejected bool `json:"untrustedForwardedHTTPSRejected"`
	ExactTrustedProxyPathUsed       bool `json:"exactTrustedProxyPathUsed"`
	HSTSOnlyAddedToSecureResponses  bool `json:"hstsOnlyAddedToSecureResponses"`
}

type response struct {
	status   int
	location string
	hsts     string
}

func main() {
	temporaryDirectory, err := os.MkdirTemp("", "bearly-transport-security-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(temporaryDirectory)

	logger, err := logging.Open(temporaryDirectory + "/app.log")
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	local := probe(logger, "http://localhost:3030", 0, "", false)
	insecure := probe(logger, productionOrigin, 1, "", false)
	directHTTPS := probe(logger, productionOrigin, 0, "", true)
	trustedForwarded := probe(logger, productionOrigin, 1, "https", false)
	untrustedForwarded := probe(logger, productionOrigin, 0, "https", false)
	twoHopSecure := probe(logger, productionOrigin, 2, "https, http", false)
	oneHopInsecure := probe(logger, productionOrigin, 1, "https, http", false)

	configuredHopCountExact, negativeHopCountRejected := configPolicy()
	environmentContents, _ := os.ReadFile(".env.example")

	output := result{
		EnvironmentDocumented:           hasExactLine(string(environmentContents), "TRUST_PROXY_HOPS=0"),
		ConfiguredHopCountExact:         configuredHopCountExact,
		NegativeHopCountRejected:        negativeHopCountRejected,
		ServerWiringConfigured:          serverWiringConfigured(),
		LocalHTTPPreserved:              local.status == http.StatusOK && local.location == "" && local.hsts == "",
		InsecureProductionRedirected:    isRedirect(insecure, productionOrigin+"/health?probe=1"),
		DirectHTTPSAccepted:             isSecureResponse(directHTTPS),
		TrustedForwardedHTTPSAccepted:   isSecureResponse(trustedForwarded),
		UntrustedForwardedHTTPSRejected: isRedirect(untrustedForwarded, productionOrigin+"/health?probe=1"),
		ExactTrustedProxyPathUsed:       isSecureResponse(twoHopSecure) && isRedirect(oneHopInsecure, productionOrigin+"/health?probe=1"),
		HSTSOnlyAddedToSecureResponses:  insecure.hsts == "" && untrustedForwarded.hsts == "" && local.hsts == "" && directHTTPS.hsts == hstsValue && trustedForwarded.hsts == hstsValue,
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		panic(err)
	}
}

func probe(logger *logging.Logger, appOrigin string, trustedProxyHops int, forwardedProtocol string, directTLS bool) response {
	options := httpserver.Options{
		AppOrigin:               appOrigin,
		MaxPublicProductResults: config.MaxPublicProductResults,
		MaxRequestBodyBytes:     config.MaxRequestBodyBytes,
		MaxUploadBytes:          config.MaxUploadBytes,
		PawPalAPIKey:            "pawpal-test-key",
		DataDirectory:           "data",
		TemplateDirectory:       "web/templates",
		PublicDirectory:         "web/public",
	}
	field := reflect.ValueOf(&options).Elem().FieldByName("TrustedProxyHops")
	if !field.IsValid() || !field.CanSet() {
		return response{}
	}
	field.SetInt(int64(trustedProxyHops))

	application, err := httpserver.New(nil, logger, options)
	if err != nil {
		panic(err)
	}
	defer application.Close()

	request := httptest.NewRequest(http.MethodGet, "http://bearly-secure.example/health?probe=1", nil)
	if forwardedProtocol != "" {
		request.Header.Set("X-Forwarded-Proto", forwardedProtocol)
	}
	if directTLS {
		request.TLS = &tls.ConnectionState{}
	}
	recorder := httptest.NewRecorder()
	application.Handler.ServeHTTP(recorder, request)
	return response{
		status:   recorder.Code,
		location: recorder.Header().Get("Location"),
		hsts:     recorder.Header().Get("Strict-Transport-Security"),
	}
}

func configPolicy() (bool, bool) {
	environment := map[string]string{
		"PAWPAL_API_KEY":       "pawpal-test-key",
		"DOWNLOAD_SIGNING_KEY": strings.Repeat("ab", 32),
		"TRUST_PROXY_HOPS":     "2",
	}
	parsed, err := config.Parse(environment, ".")
	if err != nil {
		return false, false
	}
	field := reflect.ValueOf(parsed).FieldByName("TrustedProxyHops")
	configuredHopCountExact := field.IsValid() && field.Kind() == reflect.Int && field.Int() == 2
	environment["TRUST_PROXY_HOPS"] = "-1"
	_, err = config.Parse(environment, ".")
	return configuredHopCountExact, err != nil
}

func serverWiringConfigured() bool {
	parsed, err := parser.ParseFile(token.NewFileSet(), "cmd/server/main.go", nil, 0)
	if err != nil {
		return false
	}
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		keyValue, ok := node.(*ast.KeyValueExpr)
		if !ok || identifierName(keyValue.Key) != "TrustedProxyHops" {
			return true
		}
		selector, ok := keyValue.Value.(*ast.SelectorExpr)
		found = ok && identifierName(selector.X) == "appConfig" && selector.Sel.Name == "TrustedProxyHops"
		return !found
	})
	return found
}

func identifierName(expression ast.Expr) string {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name
}

func hasExactLine(contents, expected string) bool {
	for line := range strings.SplitSeq(contents, "\n") {
		if line == expected {
			return true
		}
	}
	return false
}

func isRedirect(response response, location string) bool {
	return response.status == http.StatusPermanentRedirect && response.location == location && response.hsts == ""
}

func isSecureResponse(response response) bool {
	return response.status == http.StatusOK && response.location == "" && response.hsts == hstsValue
}
