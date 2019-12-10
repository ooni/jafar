package shellx

import "testing"

func TestIntegrationRun(t *testing.T) {
	if err := Run("whoami"); err != nil {
		t.Fatal(err)
	}
	if err := Run("./nonexistent/command"); err == nil {
		t.Fatal("expected an error here")
	}
}
