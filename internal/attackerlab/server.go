package attackerlab

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

type asset struct {
	filename    string
	contentType string
}

var assets = map[string]asset{
	"/": {
		filename: "index.html", contentType: "text/html; charset=utf-8",
	},
	"/index.html": {
		filename: "index.html", contentType: "text/html; charset=utf-8",
	},
	"/attacker-lab.css": {
		filename: "attacker-lab.css", contentType: "text/css; charset=utf-8",
	},
	"/attacker-lab.js": {
		filename: "attacker-lab.js", contentType: "text/javascript; charset=utf-8",
	},
}

type Server struct {
	root *os.Root
}

func New(directory string) (*Server, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open attacker lab directory: %w", err)
	}
	return &Server{root: root}, nil
}

func (server *Server) Close() error {
	return server.root.Close()
}

func (server *Server) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Cache-Control", "no-store")
	responseWriter.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		responseWriter.Header().Set("Allow", "GET, HEAD")
		responseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestedAsset, found := assets[request.URL.Path]
	if !found {
		responseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(responseWriter, "Not found", http.StatusNotFound)
		return
	}
	file, err := server.root.Open(requestedAsset.filename)
	if err != nil {
		responseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(responseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		responseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(responseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}
	responseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	responseWriter.Header().Set("Content-Type", requestedAsset.contentType)
	responseWriter.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(responseWriter, file)
}
