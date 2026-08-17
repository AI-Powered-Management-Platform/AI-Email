package template

import (
	"strings"
	"testing"
)

// G9 — render is a hot path: every outgoing message passes through it, on
// hostile tenant input (T11). The benchmark uses a realistic multi-tag body
// with escaping on, the way the send path calls it.
func BenchmarkRender(b *testing.B) {
	tmpl := strings.Repeat("<p>Dear {{ name }}, order {{ order_id }} ships on {{ ship_date }}.</p>\n", 50)
	variables := map[string]string{
		"name":      "សុភ័ក្រ <admin>",
		"order_id":  "ORD-2026-0001",
		"ship_date": "2026-08-20",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Render(tmpl, variables, true); err != nil {
			b.Fatal(err)
		}
	}
}
