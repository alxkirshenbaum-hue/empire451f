package vault

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecretFormatting(t *testing.T) {
	secret := PlainSecret("synthetic private value")
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x"} {
		if got := fmt.Sprintf(format, secret); got != "[REDACTED]" {
			t.Fatal("unsafe format", format)
		}
	}
	b, err := json.Marshal(struct{ Value PlainSecret }{secret})
	if err != nil || string(b) != `{"Value":"[REDACTED]"}` {
		t.Fatal("unsafe JSON")
	}
}
