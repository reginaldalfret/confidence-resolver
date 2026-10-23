package compiled_module

import (
	"fmt"
)

// Slice packing per the module ABI: low 32 bits pointer, high 32 bits length.
// The zero slice (0) means "absent".
func packSlice(ptr, length uint32) int64 {
	return int64(uint64(ptr) | uint64(length)<<32)
}

func unpackSlice(packed int64) (ptr, length uint32) {
	u := uint64(packed)
	return uint32(u & 0xffffffff), uint32(u >> 32)
}

// writeSlice allocates a block in the module's memory, copies bytes into it
// and returns the packed slice. Ownership passes to the module together with
// the call that consumes it: the module frees the request block itself.
// Must be called with the entry mutex held.
func (h *Host) writeSlice(bytes []byte) (int64, error) {
	if len(bytes) == 0 {
		return 0, nil
	}
	res, err := h.alloc.Call(h.store, len(bytes))
	if err != nil {
		return 0, fmt.Errorf("alloc(%d): %w", len(bytes), err)
	}
	ptr, ok := res.(int32)
	if !ok || ptr == 0 {
		return 0, fmt.Errorf("alloc(%d) failed", len(bytes))
	}
	data := h.memory.UnsafeData()
	if int(ptr)+len(bytes) > len(data) {
		return 0, fmt.Errorf("allocation of %d bytes is out of memory bounds", len(bytes))
	}
	copy(data[ptr:], bytes)
	return packSlice(uint32(ptr), uint32(len(bytes))), nil
}

// readSlice copies a slice out of module memory without freeing it.
// Must be called with the entry mutex held.
func (h *Host) readSlice(packed int64) ([]byte, error) {
	ptr, length := unpackSlice(packed)
	if length == 0 {
		return nil, nil
	}
	data := h.memory.UnsafeData()
	if int(ptr)+int(length) > len(data) {
		return nil, fmt.Errorf("slice of %d bytes at %d is out of memory bounds", length, ptr)
	}
	out := make([]byte, length)
	copy(out, data[ptr:ptr+length])
	return out, nil
}

// readAndFreeSlice copies a slice out of module memory and frees the block.
// Used for responses the host fully consumes (evaluate results, snapshots).
// Must be called with the entry mutex held.
func (h *Host) readAndFreeSlice(packed int64) ([]byte, error) {
	out, err := h.readSlice(packed)
	if err != nil {
		return nil, err
	}
	if _, length := unpackSlice(packed); length > 0 {
		ptr, _ := unpackSlice(packed)
		if _, err := h.frees.Call(h.store, int32(int(ptr))); err != nil {
			return nil, fmt.Errorf("free(%d): %w", ptr, err)
		}
	}
	return out, nil
}
