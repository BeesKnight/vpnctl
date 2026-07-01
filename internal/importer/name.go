package importer

import "strings"

// sanitizeName turns a URI fragment (#remark) into a filesystem-safe
// profile name. net/url already percent-decodes u.Fragment by the time it
// reaches here (re-decoding it would double-unescape literal "+" into a
// space, per the query-string "+"-means-space convention) — this just trims
// and replaces path-hostile characters.
func sanitizeName(fragment string) string {
	decoded := strings.TrimSpace(fragment)
	replacer := strings.NewReplacer(
		"/", "-", "\\", "-", ":", "-", " ", "-",
		"\t", "-", "\n", "-", "..", "-",
	)
	return replacer.Replace(decoded)
}
