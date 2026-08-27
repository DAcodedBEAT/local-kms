package service

import (
	"fmt"
	"math"
)

// ToUint16 converts n to uint16, panicking if n is out of range. Centralizing
// this lets every call site rely on a runtime-checked conversion instead of
// each repeating an unchecked cast with a "trust me, it's bounded" comment.
func ToUint16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic(fmt.Sprintf("service.ToUint16: %d out of uint16 range", n))
	}
	return uint16(n) // #nosec G115 -- range-checked immediately above.
}

// ToUint32 converts n to uint32, panicking if n is out of range. See ToUint16.
func ToUint32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic(fmt.Sprintf("service.ToUint32: %d out of uint32 range", n))
	}
	return uint32(n) // #nosec G115 -- range-checked immediately above.
}

// ToByte converts n to byte (uint8), panicking if n is out of range. See ToUint16.
func ToByte(n int) byte {
	if n < 0 || n > math.MaxUint8 {
		panic(fmt.Sprintf("service.ToByte: %d out of byte range", n))
	}
	return byte(n) // #nosec G115 -- range-checked immediately above.
}
