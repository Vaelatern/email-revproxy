package aerouter

import (
	"net/http"
	"slices"
)

type Chain []func(http.Handler) http.Handler

func (c Chain) thenFunc(h http.HandlerFunc) http.Handler {
	return c.then(h)
}
func (c Chain) then(h http.Handler) http.Handler {
	for _, mw := range slices.Backward(c) {
		h = mw(h)
	}
	return h
}
