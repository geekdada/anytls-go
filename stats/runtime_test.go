package stats

import "runtime"

// runtimeGosched is a tiny indirection so registry_test.go doesn't pull
// "runtime" into its top-of-file imports (keeps the test file focused).
func runtimeGosched() { runtime.Gosched() }
