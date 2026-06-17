package backup

import (
	"path/filepath"
	"testing"
)

func TestPathMap_LongestMatchWins(t *testing.T) {
	pm := &pathMap{}
	pm.add("/home/alice", "/Users/alice")
	pm.add("/home/alice/.quilibrium/configs", "/Users/alice/.quilibrium/configs")
	pm.finalize()

	cases := []struct {
		in, want string
		mapped   bool
	}{
		{
			in:     "/home/alice/.quilibrium/configs/node-quickstart/config.yml",
			want:   "/Users/alice/.quilibrium/configs/node-quickstart/config.yml",
			mapped: true,
		},
		{
			in:     "/home/alice/other/file",
			want:   "/Users/alice/other/file",
			mapped: true,
		},
		{
			in:     "/home/alice",
			want:   "/Users/alice",
			mapped: true,
		},
		{
			in:     "/var/lib/quilibrium/quilibrium.env",
			want:   "/var/lib/quilibrium/quilibrium.env",
			mapped: false,
		},
		{
			in:     "/home/alicex/not-matched",
			want:   "/home/alicex/not-matched",
			mapped: false,
		},
	}
	for _, tc := range cases {
		got, ok := pm.apply(tc.in)
		if got != tc.want || ok != tc.mapped {
			t.Errorf("apply(%q) = (%q,%v); want (%q,%v)",
				tc.in, got, ok, tc.want, tc.mapped)
		}
	}
}

func TestParsePathMap(t *testing.T) {
	good := []struct{ in, oldP, newP string }{
		{"/a=/b", "/a", "/b"},
		{" /foo/bar = /baz/qux ", "/foo/bar", "/baz/qux"},
	}
	for _, tc := range good {
		oldP, newP, err := parsePathMap(tc.in)
		if err != nil || oldP != tc.oldP || newP != tc.newP {
			t.Errorf("parsePathMap(%q) = (%q,%q,%v); want (%q,%q,nil)",
				tc.in, oldP, newP, err, tc.oldP, tc.newP)
		}
	}
	bad := []string{"", "no-equals", "=/b", "/a=", "relative=path", "/a=rel"}
	for _, tc := range bad {
		if _, _, err := parsePathMap(tc); err == nil {
			t.Errorf("parsePathMap(%q) expected error", tc)
		}
	}
}

func TestDestPathFor_FilesEntryRemapsToLocalConfigsDir(t *testing.T) {
	mf := &manifest{
		Version:    2,
		ConfigName: "node-quickstart",
		ConfigDir:  "/home/alice/.quilibrium/configs/node-quickstart",
		ConfigsDir: "/home/alice/.quilibrium/configs",
		Home:       "/home/alice",
	}
	bf := &backupFile{
		LocalPath: "/home/alice/.quilibrium/configs/node-quickstart/config.yml",
		ObjectKey: "node-quickstart/files/config.yml",
	}
	pm := &pathMap{}
	pm.add(mf.ConfigDir, "/Users/bob/.quilibrium/configs/node-quickstart")
	pm.finalize()
	dstConfigDir := "/Users/bob/.quilibrium/configs/node-quickstart"

	dest, mapped := destPathFor(mf, bf, pm, dstConfigDir)
	want := filepath.Join(dstConfigDir, "config.yml")
	if dest != want || !mapped {
		t.Errorf("destPathFor files entry = (%q,%v); want (%q,true)", dest, mapped, want)
	}
}

func TestDestPathFor_AbsoluteEntryUsesPathMap(t *testing.T) {
	mf := &manifest{
		Version:    2,
		ConfigName: "node-quickstart",
	}
	bf := &backupFile{
		LocalPath: "/mnt/big/store/worker-store/3/data.sst",
		ObjectKey: "node-quickstart/absolute/mnt/big/store/worker-store/3/data.sst",
	}
	pm := &pathMap{}
	pm.add("/mnt/big/store", "/data/quil/store")
	pm.finalize()

	dest, mapped := destPathFor(mf, bf, pm, "/irrelevant")
	want := "/data/quil/store/worker-store/3/data.sst"
	if dest != want || !mapped {
		t.Errorf("destPathFor abs entry = (%q,%v); want (%q,true)", dest, mapped, want)
	}
}

func TestDestPathFor_V1ManifestFallsBackToLocalPath(t *testing.T) {
	mf := &manifest{
		Version:    1,
		ConfigName: "node-quickstart",
	}
	bf := &backupFile{
		LocalPath: "/home/alice/.quilibrium/configs/node-quickstart/config.yml",
		ObjectKey: "node-quickstart/files/config.yml",
	}
	pm := &pathMap{}
	pm.finalize()
	dest, mapped := destPathFor(mf, bf, pm, "/ignored")
	if dest != bf.LocalPath || mapped {
		t.Errorf("v1 fallthrough = (%q,%v); want (%q,false)", dest, mapped, bf.LocalPath)
	}
}

func TestDestPathFor_FilesEntryWithBucketPrefix(t *testing.T) {
	mf := &manifest{
		Version:    2,
		ConfigName: "node-quickstart",
	}
	bf := &backupFile{
		LocalPath: "/home/alice/.quilibrium/configs/node-quickstart/store/LOG",
		ObjectKey: "quilibrium/backups/node-quickstart/files/store/LOG",
	}
	pm := &pathMap{}
	pm.finalize()
	dstConfigDir := "/Users/bob/.quilibrium/configs/node-quickstart"
	dest, mapped := destPathFor(mf, bf, pm, dstConfigDir)
	want := filepath.Join(dstConfigDir, "store", "LOG")
	if dest != want || !mapped {
		t.Errorf("bucket-prefixed files entry = (%q,%v); want (%q,true)", dest, mapped, want)
	}
}

func TestJoinKey(t *testing.T) {
	cases := []struct{ prefix, want string }{
		{"", "node-quickstart/files/config.yml"},
		{"/", "node-quickstart/files/config.yml"},
		{"quilibrium/backups", "quilibrium/backups/node-quickstart/files/config.yml"},
		{"/quilibrium/backups/", "quilibrium/backups/node-quickstart/files/config.yml"},
		{"  quilibrium/backups  ", "quilibrium/backups/node-quickstart/files/config.yml"},
	}
	for _, tc := range cases {
		got := joinKey(tc.prefix, "node-quickstart", "files", "config.yml")
		if got != tc.want {
			t.Errorf("joinKey(%q,...) = %q; want %q", tc.prefix, got, tc.want)
		}
	}
}

func TestNormalizeBucketPrefix(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"/":                    "",
		"//":                   "",
		"foo":                  "foo",
		"/foo/":                "foo",
		"  /foo/bar/  ":        "foo/bar",
		"quilibrium/backups":   "quilibrium/backups",
		"/quilibrium/backups/": "quilibrium/backups",
	}
	for in, want := range cases {
		if got := normalizeBucketPrefix(in); got != want {
			t.Errorf("normalizeBucketPrefix(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestBuildPathMap_UserMapOverridesAuto(t *testing.T) {
	mf := &manifest{
		Version:    2,
		ConfigName: "node-quickstart",
		ConfigDir:  "/home/alice/.quilibrium/configs/node-quickstart",
		Home:       "/home/alice",
	}
	pm, _, err := buildPathMap(mf, []string{"/home/alice=/opt/custom"})
	if err != nil {
		t.Fatalf("buildPathMap: %v", err)
	}
	got, _ := pm.apply("/home/alice/somefile")
	if got != "/opt/custom/somefile" {
		t.Errorf("user map should override auto: got %q", got)
	}
}
