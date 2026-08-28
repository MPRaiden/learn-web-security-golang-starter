package httpserver

import "net/http"

func NewServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    address,
		Handler: handler,
	}
}
