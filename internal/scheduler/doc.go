// Package scheduler contains the process-level interval runner used by the
// long-running Go services. It exists to make timing, graceful shutdown, and
// cancellation explicit instead of hiding them inside ad hoc loops.
package scheduler
