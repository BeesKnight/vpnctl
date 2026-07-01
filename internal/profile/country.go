package profile

import (
	"strings"
	"unicode"
)

// countryByCode maps common ISO 3166 alpha-2 and alpha-3 codes (plus a few
// plain-English aliases seen in real subscription/profile names) to a
// human-readable country name for display in the profile list.
var countryByCode = map[string]string{
	"nl": "Netherlands", "nld": "Netherlands", "holland": "Netherlands",
	"de": "Germany", "deu": "Germany", "germany": "Germany",
	"ch": "Switzerland", "che": "Switzerland", "switz": "Switzerland",
	"kz": "Kazakhstan", "kaz": "Kazakhstan",
	"us": "USA", "usa": "USA",
	"gb": "UK", "uk": "UK", "gbr": "UK",
	"fr": "France", "fra": "France",
	"se": "Sweden", "swe": "Sweden",
	"jp": "Japan", "jpn": "Japan",
	"sg": "Singapore", "sgp": "Singapore",
	"hk": "Hong Kong", "hkg": "Hong Kong",
	"ca": "Canada", "can": "Canada",
	"au": "Australia", "aus": "Australia",
	"fi": "Finland", "fin": "Finland",
	"pl": "Poland", "pol": "Poland",
	"tr": "Turkey", "tur": "Turkey",
	"ee": "Estonia", "est": "Estonia",
	"lv": "Latvia", "lva": "Latvia",
	"lt": "Lithuania", "ltu": "Lithuania",
	"ru": "Russia", "rus": "Russia",
	"ua": "Ukraine", "ukr": "Ukraine",
	"in": "India", "ind": "India",
	"ae": "UAE", "are": "UAE",
}

// guessCountry derives a human-readable country name from a profile's file
// name using the leading token, e.g. "nl02-mk01" -> "Netherlands",
// "germany-01" -> "Germany", "switz" -> "Switzerland". Returns "" if no
// confident match is found, in which case the raw name is shown instead.
func guessCountry(name string) string {
	token := firstToken(name)
	token = strings.TrimRightFunc(token, unicode.IsDigit)
	token = strings.ToLower(token)
	if token == "" {
		return ""
	}
	if country, ok := countryByCode[token]; ok {
		return country
	}
	return ""
}

func firstToken(name string) string {
	for i, r := range name {
		if r == '-' || r == '_' {
			return name[:i]
		}
	}
	return name
}
