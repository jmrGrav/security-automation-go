// Package recidive will hold recidivist counting and escalation policy.
//
// The current Python script uses JSON-backed counters and escalating duration
// rules. Isolating that policy now makes it easier to preserve those exact
// semantics while changing the surrounding runtime model.
package recidive
