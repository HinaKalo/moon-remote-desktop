package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func decode(body, ct string) error {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	var v struct{ Name string }
	return DecodeJSON(httptest.NewRecorder(), r, &v)
}

func TestDecodeJSON(t *testing.T) {
	cases := []struct {
		name, body, ct string
		ok             bool
	}{
		{"ok", `{"Name":"x"}`, "application/json", true},
		{"charset", `{"Name":"x"}`, "application/json; charset=utf-8", true},
		{"wrong type", `{"Name":"x"}`, "text/plain", false},
		{"unknown field", `{"Other":1}`, "application/json", false},
		{"trailing", `{"Name":"x"}{}`, "application/json", false},
		{"too big", `{"Name":"` + strings.Repeat("a", MaxBody) + `"}`, "application/json", false},
	}
	for _, c := range cases {
		if err := decode(c.body, c.ct); (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}
