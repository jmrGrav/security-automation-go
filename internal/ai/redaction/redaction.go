package redaction

// Result is the output of a future redaction pass.
type Result struct {
	Text           string
	Redactions     int
	ContainsSecret bool
}

// Redactor represents the future redaction boundary for AI prompts.
type Redactor interface {
	Redact(input string) Result
}

// Noop is a placeholder redactor used only for scaffolding and tests.
type Noop struct{}

// Redact returns the input unchanged. It exists only so the package compiles
// until a real redaction engine is introduced.
func (Noop) Redact(input string) Result {
	return Result{Text: input}
}
