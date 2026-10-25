package durable

// Windows supports control-plane tests; the execution service requires Linux.
func SyncDir(string) error { return nil }
