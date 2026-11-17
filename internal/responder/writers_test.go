package responder

import "testing"

// github-writer.json is read as the list of repositories vuln-responder can
// write (ADR 0016): only the owner and name of each entry count, and a file
// that is not that shape is an error, so the caller keeps the list it had.
func TestParseWriterConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{
			name: "other keys are ignored",
			in:   `{"appId": 1, "repositories": [{"owner": "yuanying", "name": "hshelf", "branches": ["main"]}, {"owner": "yuanying", "name": "fleet-infra"}]}`,
			want: []string{"yuanying/fleet-infra", "yuanying/hshelf"},
		},
		{name: "no repositories", in: `{"repositories": []}`, want: []string{}},
		{name: "broken JSON", in: `{"repositories": [`, wantErr: true},
		{name: "an entry without a name", in: `{"repositories": [{"owner": "yuanying"}]}`, wantErr: true},
		{name: "no repositories key", in: `{"appId": 1}`, wantErr: true},
		{name: "a missing file", in: ``, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseWriterConfig([]byte(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Errorf("accepted: %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			for _, r := range tc.want {
				if !got.Has(r) {
					t.Errorf("%s is missing from %v", r, got)
				}
			}
		})
	}
}

// GitHub's names are not case-sensitive, and an image's label may spell its
// source differently from the file.
func TestWritableIgnoresCase(t *testing.T) {
	w, err := ParseWriterConfig([]byte(`{"repositories": [{"owner": "yuanying", "name": "Penelope"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !w.Has("Yuanying/penelope") {
		t.Error("the same repository in other case is not writable")
	}
	if w.Has("yuanying/natsumi") {
		t.Error("an unlisted repository is writable")
	}
}
