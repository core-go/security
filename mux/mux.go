package mux

import (
	"github.com/gorilla/mux"
	"net/http"
)

func Handle(r *mux.Router, path string, f func(http.ResponseWriter, *http.Request), methods ...string) *mux.Route {
	return r.HandleFunc(path, f).Methods(methods...)
}
func Secure(r *mux.Router, securitySkip bool, authorize func(http.Handler, string, int32) http.Handler, check func(next http.Handler) http.Handler, path string, f func(http.ResponseWriter, *http.Request), menuId string, action int32, methods ...string) *mux.Route {
	finalHandler := http.HandlerFunc(f)
	if securitySkip {
		return r.HandleFunc(path, finalHandler).Methods(methods...)
	}
	author := func(next http.Handler) http.Handler {
		return authorize(next, menuId, action)
	}
	return r.Handle(path, check(author(finalHandler))).Methods(methods...)
}
