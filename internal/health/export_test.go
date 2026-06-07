package health

// DiskStatfsOverride allows tests to inject a fake diskStatfs implementation.
// Only use in tests.
var DiskStatfsOverride = &diskStatfs
