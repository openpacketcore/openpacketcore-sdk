package testing

// FakeClock is a test-time source.
type FakeClock struct{}

// Now returns a fixed time.
func (f *FakeClock) Now() string {
	return "2026-06-11T00:00:00Z"
}
