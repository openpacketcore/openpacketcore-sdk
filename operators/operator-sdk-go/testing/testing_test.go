package testing

import "testing"

func TestFakeClock(t *testing.T) {
	fc := &FakeClock{}
	if fc.Now() == "" {
		t.Fatal("expected non-empty time")
	}
}
