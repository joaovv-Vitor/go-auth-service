package clock

import "time"

// Clock provides the current time to components whose behavior depends on it.
type Clock interface {
	Now() time.Time
}

// System uses the operating system clock.
type System struct{}

func (System) Now() time.Time {
	return time.Now().UTC()
}

// Func adapts a function into a Clock.
type Func func() time.Time

func (f Func) Now() time.Time {
	return f().UTC()
}
