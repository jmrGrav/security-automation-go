// Package state owns persistence during the first migration phase.
//
// This package starts with JSON storage because the Python scripts already rely
// on local JSON state files. Keeping persistence behind an interface now makes
// it possible to swap SQLite in later without changing service code.
package state
