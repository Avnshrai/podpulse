// Package slack ships PodPulse anomalies to a Slack incoming webhook.
//
// This is a minimal implementation: it formats the anomaly into a
// Block-Kit-style payload using only the bits Slack guarantees on
// incoming-webhook URLs, so it works equally well with a workspace's
// "Incoming Webhooks" app and with the bot-token webhook variant.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

const channelName = "slack"

type Sender struct {
	webhook string
	client  *http.Client
}

func New(webhookURL string) *Sender {
	return &Sender{
		webhook: webhookURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Sender) Name() string { return channelName }

func (s *Sender) Send(ctx context.Context, a types.Anomaly) error {
	if s.webhook == "" {
		return fmt.Errorf("slack webhook not configured")
	}

	payload := map[string]any{
		"text":   fallbackText(a),
		"blocks": blocks(a),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

func fallbackText(a types.Anomaly) string {
	return fmt.Sprintf("[%s] %s on %s", strings.ToUpper(string(a.Severity)), a.Kind, a.Workload)
}

func blocks(a types.Anomaly) []map[string]any {
	header := fmt.Sprintf(":rotating_light: *PodPulse anomaly* — %s on `%s`",
		string(a.Kind), a.Workload)

	body := a.RCA
	if body == "" {
		body = "(no RCA available)"
	}

	out := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": header}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": body}},
	}

	if a.Template != "" {
		out = append(out, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Template*\n```%s```", a.Template),
			},
		})
	}

	if len(a.Suggestions) > 0 {
		var b strings.Builder
		b.WriteString("*Suggested investigation steps*")
		for i, s := range a.Suggestions {
			if i >= 4 {
				b.WriteString("\n_…and more in the dashboard_")
				break
			}
			b.WriteString("\n• *")
			b.WriteString(s.Title)
			b.WriteString("*")
			if s.Command != "" {
				b.WriteString("\n```")
				b.WriteString(s.Command)
				b.WriteString("```")
			}
		}
		out = append(out, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": b.String()},
		})
	}

	out = append(out, map[string]any{
		"type": "context",
		"elements": []map[string]any{
			{"type": "mrkdwn", "text": fmt.Sprintf("severity: *%s* · pods: %d · id: `%s`",
				a.Severity, a.AffectedPods, a.ID)},
		},
	})
	return out
}
