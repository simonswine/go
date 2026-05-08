// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Pool guard: GODEBUG=poolguard=1 detects use-after-Pool.Put bugs.
//
// When enabled, the backing arrays of pool items are moved to dedicated
// mmap-backed pages on Put, and those pages are made inaccessible.
// Any subsequent access (same-goroutine or cross-goroutine) before the
// next Pool.Get is caught and reported with both the access site and
// the Pool.Put stack.
//
// Platform behaviour:
//   - Linux: pages are made inaccessible via madvise(MADV_DONTNEED) and
//     registered with a userfaultfd so that faults are handled gracefully
//     by a background goroutine (the program can optionally continue).
//   - Other Unix: mprotect(PROT_NONE) + SIGSEGV; the signal handler calls
//     poolGuardReport then throws.
//   - Windows: no-op (TODO).

package runtime

import (
	"internal/abi"
	"unsafe"
)

// poolGuardSuppressPattern describes one entry from POOLGUARD_SUPPRESS.
type poolGuardSuppressPattern struct {
	pat         string // pattern to match
	directOnly  bool   // if true, match only the direct Pool.Put caller
}

// poolGuardSuppressPatterns holds patterns parsed from POOLGUARD_SUPPRESS.
// Entries are immutable after init.
var poolGuardSuppressPatterns []poolGuardSuppressPattern

// poolGuardInitSuppressPatterns parses the POOLGUARD_SUPPRESS env var.
//
// Two pattern forms are supported:
//
//	net/http                     prefix match — suppress any Put whose call
//	                             stack contains a frame whose function name
//	                             starts with "net/http" (broad).
//
//	=net/http.putBufioWriter     direct-caller match — suppress only when
//	                             the function that directly calls Pool.Put
//	                             starts with "net/http.putBufioWriter" (precise).
//
// The two forms compose: use package prefixes for convenience or full
// function names for exactness:
//
//	POOLGUARD_SUPPRESS==fmt.(*pp).free,=net/http.putBufioWriter
func poolGuardInitSuppressPatterns() {
	env := gogetenv("POOLGUARD_SUPPRESS")
	if env == "" {
		return
	}
	start := 0
	for i := 0; i <= len(env); i++ {
		if i == len(env) || env[i] == ',' {
			if i > start {
				raw := env[start:i]
				if len(raw) > 0 && raw[0] == '=' {
					poolGuardSuppressPatterns = append(poolGuardSuppressPatterns,
						poolGuardSuppressPattern{pat: raw[1:], directOnly: true})
				} else {
					poolGuardSuppressPatterns = append(poolGuardSuppressPatterns,
						poolGuardSuppressPattern{pat: raw, directOnly: false})
				}
			}
			start = i + 1
		}
	}
}

// poolGuardHasPrefix reports whether s starts with prefix.
func poolGuardHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// poolGuardSuppressed reports whether the Put call stack represented by pcs
// should be suppressed.
//
// pcs[0] is always sync.(*Pool).Put; pcs[1] is the direct Pool.Put caller.
// "="-prefixed patterns match only pcs[1]; plain patterns match any frame.
func poolGuardSuppressed(pcs []uintptr) bool {
	if len(poolGuardSuppressPatterns) == 0 || len(pcs) == 0 {
		return false
	}

	// Pre-compute the direct-caller name (pcs[1]) only if needed.
	directName := ""
	for _, sp := range poolGuardSuppressPatterns {
		if !sp.directOnly {
			continue
		}
		if directName == "" && len(pcs) > 1 && pcs[1] != 0 {
			if f := findfunc(pcs[1]); f.valid() {
				directName = funcname(f)
			}
		}
		if directName != "" && poolGuardHasPrefix(directName, sp.pat) {
			return true
		}
	}

	// Check any-frame patterns.
	for _, sp := range poolGuardSuppressPatterns {
		if sp.directOnly {
			continue
		}
		for _, pc := range pcs {
			if pc == 0 {
				break
			}
			f := findfunc(pc)
			if !f.valid() {
				continue
			}
			if poolGuardHasPrefix(funcname(f), sp.pat) {
				return true
			}
		}
	}
	return false
}

// poolGuardPage tracks one mmap-backed guarded region.
// Entries are added on first Put of a pool item and never removed;
// the same entry is reused on subsequent Put/Get cycles.
type poolGuardPage struct {
	next      *poolGuardPage
	base      uintptr    // start of mmap region (page-aligned)
	size      uintptr    // size of mmap region (page-aligned)
	protected bool       // currently inaccessible?
	putPCs    [16]uintptr // call stack at most recent Put
	nPCs      int
}

var (
	poolGuardMu   mutex
	poolGuardList *poolGuardPage // all known guard pages (permanent)
)

// poolGuardFind returns the guard entry whose region contains addr, or nil.
// Must be safe to call with no stack growth (signal context).
//
//go:nosplit
func poolGuardFind(addr uintptr) *poolGuardPage {
	// No lock — called from SIGSEGV handler.  Concurrent modification of
	// poolGuardList is accepted: the worst outcome is a missed detection.
	for p := poolGuardList; p != nil; p = p.next {
		if addr >= p.base && addr < p.base+p.size {
			return p
		}
	}
	return nil
}

// poolGuardReport prints a detailed "use after Pool.Put" report and
// terminates the program.  Called from sigpanic when a fault lands in a
// guarded region.
func poolGuardReport(r *poolGuardPage, faultAddr uintptr) {
	print("\n==================\n")
	print("WARNING: accessed pool buffer after Pool.Put\n\n")
	gp := getg()
	print("Current goroutine (goroutine ", gp.goid, "):\n")
	// Print the current access stack via tracebackothers won't work here;
	// sigpanic will do that.  We just annotate with the Put site.
	print("\nBuffer was Put at:\n")
	for i := 0; i < r.nPCs; i++ {
		pc := r.putPCs[i]
		if pc == 0 {
			break
		}
		f := findfunc(pc)
		if !f.valid() {
			print("  [unknown ", hex(pc), "]\n")
			continue
		}
		file, line := funcline(f, pc-1)
		print("  ", funcname(f), "\n\t", file, ":", line, "\n")
	}
	print("\nFault address: ", hex(faultAddr), "\n")
	print("==================\n\n")
	throw("use after Pool.Put")
}

// poolGuardAllocPages allocates n bytes of anonymous memory that is
// page-aligned and returns a pointer to it.  Returns nil on failure.
func poolGuardAllocPages(n uintptr) unsafe.Pointer {
	n = (n + physPageSize - 1) &^ (physPageSize - 1)
	p, err := mmap(nil, n, _PROT_READ|_PROT_WRITE, _MAP_ANON|_MAP_PRIVATE, -1, 0)
	if err != 0 {
		return nil
	}
	return p
}

// poolGuardAddKnown records a new mmap region and returns its entry.
func poolGuardAddKnown(base, size uintptr) *poolGuardPage {
	r := new(poolGuardPage)
	r.base = base
	r.size = size
	lock(&poolGuardMu)
	r.next = poolGuardList
	poolGuardList = r
	unlock(&poolGuardMu)
	return r
}

// poolGuardLookup returns the entry for a known mmap region containing addr,
// or nil.  Unlike poolGuardFind, this takes the lock.
func poolGuardLookup(addr uintptr) *poolGuardPage {
	lock(&poolGuardMu)
	for p := poolGuardList; p != nil; p = p.next {
		if addr >= p.base && addr < p.base+p.size {
			unlock(&poolGuardMu)
			return p
		}
	}
	unlock(&poolGuardMu)
	return nil
}

// poolGuardPutBacking is the platform-independent part of protecting a single
// slice backing array.  It moves the data to mmap pages (if not already), then
// calls the platform-specific protection function.
func poolGuardPutBacking(hdrData *unsafe.Pointer, hdrCap int, elemSize uintptr) {
	orig := uintptr(*hdrData)
	if orig == 0 || hdrCap == 0 || elemSize == 0 {
		return
	}
	dataSize := uintptr(hdrCap) * elemSize

	// Capture the Put call stack before any other work so the suppression
	// check and the error report both use the same frames.
	var putPCs [16]uintptr
	nPCs := callers(4, putPCs[:])

	// Check whether the caller's package is on the suppression list.
	// If so, skip protection silently (the pattern is known-safe).
	if poolGuardSuppressed(putPCs[:nPCs]) {
		return
	}

	// Check whether this backing array is already one of our mmap regions.
	r := poolGuardLookup(orig)
	if r == nil {
		// First time: allocate mmap pages and copy data there.
		newBase := poolGuardAllocPages(dataSize)
		if newBase == nil {
			return // allocation failure, skip guarding
		}
		memmove(newBase, *hdrData, dataSize)
		pageSize := (dataSize + physPageSize - 1) &^ (physPageSize - 1)
		r = poolGuardAddKnown(uintptr(newBase), pageSize)
		// Update the caller's slice header to point at the new pages.
		*hdrData = newBase
	}

	// Store the Put call stack for the fault report.
	r.nPCs = copy(r.putPCs[:], putPCs[:nPCs])
	r.protected = true

	// Delegate to platform-specific protection (mprotect or userfaultfd).
	poolGuardProtect(unsafe.Pointer(r.base), r.size, r)
}

// poolGuardGetBacking unprotects the mmap pages for a backing array.
func poolGuardGetBacking(data unsafe.Pointer) {
	if data == nil {
		return
	}
	r := poolGuardLookup(uintptr(data))
	if r == nil || !r.protected {
		return
	}
	r.protected = false
	poolGuardUnprotect(unsafe.Pointer(r.base), r.size)
}

// sliceHeader mirrors the slice header layout.  Used to read/write Data
// without triggering checkptr (same pattern as in sync/pool.go).
type pgSliceHeader struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

// poolGuardPutSliceFields walks the struct at base (described by typ) and
// calls poolGuardPutBacking for every heap-allocated []byte field.
func poolGuardPutSliceFields(base unsafe.Pointer, typ *abi.Type) {
	st := typ.StructType()
	if st == nil {
		return
	}
	for i := range st.Fields {
		f := &st.Fields[i]
		fieldPtr := unsafe.Pointer(uintptr(base) + f.Offset)
		switch f.Typ.Kind() {
		case abi.Slice:
			hdr := (*pgSliceHeader)(fieldPtr)
			if hdr.Data == nil || hdr.Cap == 0 {
				continue
			}
			if !inheap(uintptr(hdr.Data)) {
				// Non-heap backing array (SRODATA etc.) — skip.
				continue
			}
			elemSize := (*abi.SliceType)(unsafe.Pointer(f.Typ)).Elem.Size_
			if elemSize == 0 {
				continue
			}
			poolGuardPutBacking(&hdr.Data, hdr.Cap, elemSize)
		case abi.Struct:
			poolGuardPutSliceFields(fieldPtr, f.Typ)
		}
	}
}

// poolGuardGetSliceFields unprotects all slice backing arrays within base.
func poolGuardGetSliceFields(base unsafe.Pointer, typ *abi.Type) {
	st := typ.StructType()
	if st == nil {
		return
	}
	for i := range st.Fields {
		f := &st.Fields[i]
		fieldPtr := unsafe.Pointer(uintptr(base) + f.Offset)
		switch f.Typ.Kind() {
		case abi.Slice:
			hdr := (*pgSliceHeader)(fieldPtr)
			poolGuardGetBacking(hdr.Data)
		case abi.Struct:
			poolGuardGetSliceFields(fieldPtr, f.Typ)
		}
	}
}

// sync_poolGuardPut is called from sync.Pool.Put when GODEBUG=poolguard=1.
// typPtr and dataPtr are the raw interface words of the pool item.
//
//go:linkname sync_poolGuardPut sync.runtime_poolGuardPut
func sync_poolGuardPut(typPtr, dataPtr unsafe.Pointer) {
	typ := (*abi.Type)(typPtr)
	switch typ.Kind() {
	case abi.Pointer:
		elemTyp := (*abi.PtrType)(unsafe.Pointer(typ)).Elem
		if elemTyp.Size_ > 0 && elemTyp.Kind() == abi.Struct {
			poolGuardPutSliceFields(dataPtr, elemTyp)
		}
	case abi.Slice:
		if dataPtr == nil {
			return
		}
		hdr := (*pgSliceHeader)(dataPtr)
		if hdr.Data == nil || hdr.Cap == 0 {
			return
		}
		elemSize := (*abi.SliceType)(unsafe.Pointer(typ)).Elem.Size_
		if elemSize == 0 {
			return
		}
		if !inheap(uintptr(hdr.Data)) {
			return
		}
		poolGuardPutBacking(&hdr.Data, hdr.Cap, elemSize)
	}
}

// sync_poolGuardGet is called from sync.Pool.Get when GODEBUG=poolguard=1.
//
//go:linkname sync_poolGuardGet sync.runtime_poolGuardGet
func sync_poolGuardGet(typPtr, dataPtr unsafe.Pointer) {
	typ := (*abi.Type)(typPtr)
	switch typ.Kind() {
	case abi.Pointer:
		elemTyp := (*abi.PtrType)(unsafe.Pointer(typ)).Elem
		if elemTyp.Size_ > 0 && elemTyp.Kind() == abi.Struct {
			poolGuardGetSliceFields(dataPtr, elemTyp)
		}
	case abi.Slice:
		if dataPtr == nil {
			return
		}
		hdr := (*pgSliceHeader)(dataPtr)
		poolGuardGetBacking(hdr.Data)
	}
}

// sync_poolGuardEnabled reports whether GODEBUG=poolguard=1 is active.
//
//go:linkname sync_poolGuardEnabled sync.runtime_poolGuardEnabled
//go:nosplit
func sync_poolGuardEnabled() bool {
	return debug.poolguard != 0
}

func init() {
	if debug.poolguard != 0 {
		poolGuardInitSuppressPatterns()
	}
}
