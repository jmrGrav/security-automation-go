// Package abuseipdb defines the reporting seam used by the current Python
// daemon. Keeping the reporting interface small makes it easy to preserve the
// current deduplication and category-mapping behavior while postponing the
// actual HTTP implementation to a later migration step.
package abuseipdb
