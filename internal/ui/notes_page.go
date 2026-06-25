package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

// handleNotesPage serves GET /notes — lists all operator notes.
func (s *Server) handleNotesPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var notes []sqlite.Note
	if s.noteStore != nil {
		var err error
		notes, err = s.noteStore.List(ctx)
		if err != nil {
			http.Error(w, "failed to load notes", http.StatusInternalServerError)
			return
		}
	}
	_ = NotesPage(notes).Render(ctx, w)
}

// handleNoteUpsert serves POST /notes — creates or updates a note.
func (s *Server) handleNoteUpsert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	entityType := r.PostFormValue("type")
	entityValue := r.PostFormValue("value")
	content := r.PostFormValue("content")

	if entityType == "" || entityValue == "" {
		http.Error(w, "type and value are required", http.StatusBadRequest)
		return
	}

	if s.noteStore != nil {
		if err := s.noteStore.Upsert(ctx, entityType, entityValue, content); err != nil {
			http.Error(w, "failed to save note", http.StatusInternalServerError)
			return
		}
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/notes"
	}
	http.Redirect(w, r, referer, http.StatusSeeOther)
}

// handleNoteDelete serves POST /notes/delete — removes a note by entity type+value.
func (s *Server) handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entityType := r.URL.Query().Get("type")
	entityValue := r.URL.Query().Get("value")

	if entityType != "" && entityValue != "" && s.noteStore != nil {
		_ = s.noteStore.Delete(ctx, entityType, entityValue)
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/notes"
	}
	http.Redirect(w, r, referer, http.StatusSeeOther)
}

// NotesPage renders the full operator notes list page.
func NotesPage(notes []sqlite.Note) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Operator Notes",
		Headline: "Operator Notes",
		Subtitle: "Annotations attached to IPs, ASNs, and other entities. Never influence provider decisions.",
		Active:   "/notes",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if len(notes) == 0 {
				return writeEmptyState(w, "No notes yet. Use the form on a Forensic or Intelligence page to annotate an entity.")
			}
			if _, err := fmt.Fprint(w, `<div class="panel"><h2>All Operator Notes</h2><div class="table-wrap"><table><colgroup><col style="width:6rem"><col style="width:12rem"><col><col style="width:10rem"><col style="width:7rem"></colgroup><thead><tr><th>Type</th><th>Entity</th><th>Note</th><th>Updated</th><th>Action</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, n := range notes {
				deleteURL := fmt.Sprintf("/notes/delete?type=%s&value=%s",
					url.QueryEscape(n.EntityType),
					url.QueryEscape(n.EntityValue),
				)
				if _, err := fmt.Fprintf(w,
					`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><form method="post" action="%s"><button type="submit" class="badge warning">Delete</button></form></td></tr>`,
					html.EscapeString(n.EntityType),
					html.EscapeString(n.EntityValue),
					html.EscapeString(n.Content),
					html.EscapeString(n.UpdatedAt.Format("2006-01-02 15:04")),
					deleteURL,
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table></div></div>`)
			return err
		}),
	})
}

// NoteFormHTML returns an HTML snippet for embedding a note upsert form on
// other pages (e.g. the forensic page). All values are HTML-escaped.
// currentContent is the existing note text (empty string if no note yet).
func NoteFormHTML(entityType, entityValue, currentContent string) string {
	return fmt.Sprintf(
		`<div class="panel"><h2>Operator Note</h2>`+
			`<form method="post" action="/notes">`+
			`<input type="hidden" name="type" value="%s"/>`+
			`<input type="hidden" name="value" value="%s"/>`+
			`<label for="op-note-content">Note</label>`+
			`<textarea id="op-note-content" name="content" rows="4" style="width:100%%">%s</textarea>`+
			`<button type="submit">Save note</button>`+
			`</form></div>`,
		html.EscapeString(entityType),
		html.EscapeString(entityValue),
		html.EscapeString(currentContent),
	)
}
