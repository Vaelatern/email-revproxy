package aerouter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChain(t *testing.T) {
	used := ""

	mw1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			used += "1"
			next.ServeHTTP(w, r)
		})
	}

	mw2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			used += "2"
			next.ServeHTTP(w, r)
		})
	}

	mw3 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			used += "3"
			next.ServeHTTP(w, r)
		})
	}

	mw4 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			used += "4"
			next.ServeHTTP(w, r)
		})
	}

	mw5 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			used += "5"
			next.ServeHTTP(w, r)
		})
	}

	mw6 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			used += "6"
			next.ServeHTTP(w, r)
		})
	}

	hf := func(w http.ResponseWriter, r *http.Request) {}

	m := http.NewServeMux()

	c1 := Chain{mw1, mw2}

	m.Handle("GET /{$}", c1.thenFunc(hf))

	c2 := append(c1, mw3, mw4)
	m.Handle("GET /foo", c2.thenFunc(hf))

	c3 := append(c2, mw5)
	m.Handle("GET /nested/foo", c3.thenFunc(hf))

	c4 := append(c1, mw6)
	m.Handle("GET /bar", c4.thenFunc(hf))

	m.Handle("GET /baz", c1.thenFunc(hf))

	var tests = []struct {
		RequestMethod  string
		RequestPath    string
		ExpectedUsed   string
		ExpectedStatus int
	}{
		{
			RequestMethod:  "GET",
			RequestPath:    "/",
			ExpectedUsed:   "12",
			ExpectedStatus: http.StatusOK,
		},
		{
			RequestMethod:  "GET",
			RequestPath:    "/foo",
			ExpectedUsed:   "1234",
			ExpectedStatus: http.StatusOK,
		},
		{
			RequestMethod:  "GET",
			RequestPath:    "/nested/foo",
			ExpectedUsed:   "12345",
			ExpectedStatus: http.StatusOK,
		},
		{
			RequestMethod:  "GET",
			RequestPath:    "/bar",
			ExpectedUsed:   "126",
			ExpectedStatus: http.StatusOK,
		},
		{
			RequestMethod:  "GET",
			RequestPath:    "/baz",
			ExpectedUsed:   "12",
			ExpectedStatus: http.StatusOK,
		},
	}

	for _, test := range tests {
		used = ""

		r, err := http.NewRequest(test.RequestMethod, test.RequestPath, nil)
		if err != nil {
			t.Errorf("NewRequest: %s", err)
		}

		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, r)

		rs := rr.Result()

		if rs.StatusCode != test.ExpectedStatus {
			t.Errorf("%s %s: expected status %d but was %d", test.RequestMethod, test.RequestPath, test.ExpectedStatus, rs.StatusCode)
		}

		if used != test.ExpectedUsed {
			t.Errorf("%s %s: middleware used: expected %q; got %q", test.RequestMethod, test.RequestPath, test.ExpectedUsed, used)
		}
	}
}
