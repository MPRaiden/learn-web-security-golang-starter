package attackerlab

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestServerServesOnlyKnownAssets(t *testing.T) {
	_, currentFilename, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFilename), "..", ".."))
	server, err := New(filepath.Join(projectRoot, "attacker-lab"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { server.Close() })

	indexRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	indexResponse := httptest.NewRecorder()
	server.ServeHTTP(indexResponse, indexRequest)
	if indexResponse.Code != http.StatusOK || !strings.Contains(indexResponse.Body.String(), "Bearly Evil") {
		t.Fatalf("index response = %d %q", indexResponse.Code, indexResponse.Body.String())
	}
	if indexResponse.Header().Get("Cache-Control") != "no-store" || indexResponse.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("index headers = %v", indexResponse.Header())
	}

	headRequest := httptest.NewRequest(http.MethodHead, "/attacker-lab.js", nil)
	headResponse := httptest.NewRecorder()
	server.ServeHTTP(headResponse, headRequest)
	if headResponse.Code != http.StatusOK || headResponse.Body.Len() != 0 || headResponse.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("head response = %d %q %q", headResponse.Code, headResponse.Body.String(), headResponse.Header().Get("Content-Type"))
	}

	missingRequest := httptest.NewRequest(http.MethodGet, "/missing", nil)
	missingResponse := httptest.NewRecorder()
	server.ServeHTTP(missingResponse, missingRequest)
	if missingResponse.Code != http.StatusNotFound {
		t.Errorf("missing response = %d", missingResponse.Code)
	}

	postRequest := httptest.NewRequest(http.MethodPost, "/", nil)
	postResponse := httptest.NewRecorder()
	server.ServeHTTP(postResponse, postRequest)
	if postResponse.Code != http.StatusMethodNotAllowed || postResponse.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("post response = %d, allow %q", postResponse.Code, postResponse.Header().Get("Allow"))
	}
}
