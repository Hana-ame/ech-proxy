package cloudflare_ech

import (
	"net/http"
	"testing"
)

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

func TestZeroValueClientDoReturnsErrorWithoutPanic(t *testing.T) {
	var zero Client
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zero.Do(req); err == nil {
		t.Fatal("expected error from zero-value Client.Do, got nil")
	}
}
