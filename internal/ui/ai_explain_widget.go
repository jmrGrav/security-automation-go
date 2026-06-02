package ui

import (
	"fmt"
	"html"
	"io"
)

func renderAIExplainWidget(w io.Writer, subjectType, subjectID, csrfToken, summary string) error {
	if _, err := fmt.Fprint(w, `<div class="panel ai-explain" data-ai-explain-block>`); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
		return err
	}
	rows := []keyValueRow{
		{Key: "Subject type", Value: subjectType},
		{Key: "Subject id", Value: subjectID},
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(row.Key), html.EscapeString(valueOrUnknown(row.Value))); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, `</div>`); err != nil {
		return err
	}
	if summary != "" {
		if _, err := fmt.Fprintf(w, `<p class="muted">%s</p>`, html.EscapeString(summary)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, `<form action="/ui/ai/explain" method="post" data-ai-explain-form><input type="hidden" name="subject_type" value="%s"/><input type="hidden" name="subject_id" value="%s"/><input type="hidden" name="provider_preference" value="auto"/><input type="hidden" name="csrf_token" value="%s"/><button type="submit">Explain with AI</button></form>`, html.EscapeString(subjectType), html.EscapeString(subjectID), html.EscapeString(csrfToken)); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<div class="empty" data-ai-explain-result>AI explanation not requested yet.</div></div>`); err != nil {
		return err
	}
	return nil
}
