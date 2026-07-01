package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func withTempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAllGroupsAndSortsProfiles(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()

	writeFile(t, filepath.Join(base, "wg", "switz.conf"), amneziaConf)
	writeFile(t, filepath.Join(base, "wg", "germany-01.conf"), plainWGConf)
	writeFile(t, filepath.Join(base, "proxy", "nl02-mk01.json"), `{"type":"vless","server":"1.2.3.4","server_port":443,"uuid":"x"}`)
	writeFile(t, filepath.Join(base, "proxy", "kz03-hy01.json"), `{"type":"hysteria2","server":"5.6.7.8","server_port":443,"password":"x"}`)

	profiles, err := LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(profiles) != 4 {
		t.Fatalf("expected 4 profiles, got %d: %+v", len(profiles), profiles)
	}

	// Group order must be WG/AmneziaWG, then VLESS, then Hysteria2, 
	// sorted by name within each group.
	wantOrder := []string{"germany-01", "switz", "nl02-mk01", "kz03-hy01"}
	for i, name := range wantOrder {
		if profiles[i].Name != name {
			t.Errorf("position %d: expected %q, got %q", i, name, profiles[i].Name)
		}
	}
}

func TestLoadAllSkipsUnparseableFilesInstedOfFailing(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()
	writeFile(t, filepath.Join(base, "wg", "broken.conf"), "not a valid wg conf")
	writeFile(t, filepath.Join(base, "wg", "switz.conf"), amneziaConf)

	profiles, err := LoadAll()
	if err != nil {
		t.Fatalf("LoadAll should skip broken files, not fail: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "switz" {
		t.Fatalf("expected only the valid profile to load, got %+v", profiles)
	}
}

func TestFindReturnsProfileByName(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()
	writeFile(t, filepath.Join(base, "wg", "switz.conf"), amneziaConf)

	p, err := Find("switz")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if p.Kind != KindAmneziaWG {
		t.Errorf("expected AmneziaWG, got %s", p.Kind)
	}

	if _, err := Find("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown profile name")
	}
}

func TestMetaSidecarOverridesCountryAndLabel(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()
	writeFile(t, filepath.Join(base, "wg", "mystery.conf"), amneziaConf)
	writeFile(t, filepath.Join(base, "wg", "mystery.yaml"), "country: Wonderland\nlabel: My Secret Node\n")

	p, err := Find("mystery")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if p.Country != "Wonderland" {
		t.Errorf("expected meta override country Wonderland, got %s", p.Country)
	}
	if p.DisplayName() != "My Secret Node (Wonderland)" {
		t.Errorf("unexpected display name: %s", p.DisplayName())
	}
}

func TestGuessCountryFromFileName(t *testing.T) {
	cases := map[string]string{
		"switz":       "Switzerland",
		"germany-01":  "Germany",
		"nl02-mk01":   "Netherlands",
		"che01-mk01":  "Switzerland",
		"kz03-hy01":   "Kazakhstan",
		"unknownxyz":  "",
		"nl01-ntr-hy": "Netherlands",
	}
	for name, want := range cases {
		if got := guessCountry(name); got != want {
			t.Errorf("guessCountry(%q) = %q, want %q", name, got, want)
		}
	}
}
