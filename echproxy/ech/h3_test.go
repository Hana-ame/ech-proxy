package cloudflare_ech

import "testing"

func TestECHHTTP3DefaultOffAndToggle(t *testing.T) {
	t.Cleanup(func() {
		SetECHHTTP3(false)
	})
	SetECHHTTP3(false)
	if GetECHHTTP3() {
		t.Fatalf("expected ECH HTTP/3 fallback to default to false")
	}
	SetECHHTTP3(true)
	if !GetECHHTTP3() {
		t.Fatalf("expected ECH HTTP/3 fallback to become true after SetECHHTTP3(true)")
	}
	SetECHHTTP3(false)
	if GetECHHTTP3() {
		t.Fatalf("expected ECH HTTP/3 fallback to become false after SetECHHTTP3(false)")
	}
}
