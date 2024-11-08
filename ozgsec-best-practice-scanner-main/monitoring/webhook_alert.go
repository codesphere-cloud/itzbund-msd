package monitoring

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func SendSlackWebhookAlert(message string) error {
	var webhook string = os.Getenv("SLACK_WEBHOOK")
	if webhook == "" {
		return fmt.Errorf("SLACK_WEBHOOK is not set - cannot send slack webhook alert")
	}

	m := `{"text":"` + message + `"}`
	_, err := http.Post(webhook, "application/json", strings.NewReader(m)) // nolint // we are trusting the env var.
	return err
}
