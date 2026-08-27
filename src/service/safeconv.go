package service

import "fmt"

// unsignedConv is the set of unsigned integer types ToUnsigned can target.
type unsignedConv interface {
	~uint8 | ~uint16 | ~uint32
}

// ToUnsigned converts n to T, panicking if n is out of T's range. Centralizing
// this lets call sites rely on a runtime-checked conversion instead of each
// repeating an unchecked cast with a "trust me, it's bounded" comment.
func ToUnsigned[T unsignedConv](n int) T {
	var limit T
	limit-- // wraps 0 to all-ones, i.e. T's maximum value

	if n < 0 || uint64(n) > uint64(limit) {
		panic(fmt.Sprintf("service.ToUnsigned: %d out of range for %T", n, limit))
	}
	return T(n) // #nosec G115 -- range-checked immediately above.
}
