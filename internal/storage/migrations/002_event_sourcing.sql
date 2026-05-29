-- Version: 002
-- Description: Add event sourcing table

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    category TEXT NOT NULL,
    type TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    causal_id TEXT,
    actor TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    metadata TEXT,
    UNIQUE(scope_id, sequence)
);

CREATE INDEX idx_events_correlation ON events(correlation_id);
CREATE INDEX idx_events_scope_seq ON events(scope_id, sequence);
