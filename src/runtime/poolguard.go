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
//
// Standard library and common framework pools that are known-safe and should
// be suppressed when running against typical Go applications:
//
//	fmt,regexp,sync,net,encoding,compress,crypto,bytes,strings,io,
//	google.golang.org/grpc,google.golang.org/protobuf,
//	connectrpc.com,github.com/parquet-go,github.com/prometheus,
//	github.com/grafana/dskit
//
// These packages access pooled slice backing arrays after Pool.Put, but do
// so safely — no alias escapes the Put boundary.  Application-level pools
// (like Pyroscope's bufferpool) should NOT appear in this list.
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
// "="-prefixed patterns match only the direct Pool.Put caller.
// Plain patterns match any frame in the stack.
//
// The direct Pool.Put caller sits at different indices depending on the code
// path through poolguard:
//   - *Struct pool (via poolGuardPutSliceFields): pcs[0]=sync.(*Pool).Put,
//     pcs[1]=direct caller.
//   - []byte pool (direct from sync_poolGuardPut): pcs[0]=direct caller,
//     pcs[1]=caller's caller.
//
// For directOnly patterns we therefore check both pcs[0] and pcs[1]; the
// pattern must start with the function name (not "sync.") to avoid
// accidentally matching Pool.Put itself.
func poolGuardSuppressed(pcs []uintptr) bool {
	if len(poolGuardSuppressPatterns) == 0 || len(pcs) == 0 {
		return false
	}

	// For "="-prefixed patterns: check the first two frames, taking whichever
	// is not sync.(*Pool).Put (which is always in the chain but not the caller
	// we care about for suppression purposes).
	for _, sp := range poolGuardSuppressPatterns {
		if !sp.directOnly {
			continue
		}
		for i := 0; i < 2 && i < len(pcs); i++ {
			if pcs[i] == 0 {
				break
			}
			f := findfunc(pcs[i])
			if !f.valid() {
				continue
			}
			name := funcname(f)
			// Skip the Pool.Put frame itself.
			if poolGuardHasPrefix(name, "sync.(*Pool).") {
				continue
			}
			if poolGuardHasPrefix(name, sp.pat) {
				return true
			}
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

// poolGuardGetBacking ensures the slice field at hdrData is backed by
// page-isolated mmap memory before the caller uses the pool item.
//
// If the backing array is already one of our mmap regions: unprotect it
// so the caller can read/write normally.
//
// If it is a plain heap allocation: migrate it to a fresh mmap region now,
// updating hdrData so the caller's pointer is redirected.  Any aliases the
// caller creates between Get and Put will then point into the mmap region.
// When Put calls poolGuardPutBacking, it just mprotects those pages.
func poolGuardGetBacking(hdrData *unsafe.Pointer, hdrCap int, elemSize uintptr) {
	if *hdrData == nil || hdrCap == 0 || elemSize == 0 {
		return
	}
	orig := uintptr(*hdrData)

	r := poolGuardLookup(orig)
	if r != nil {
		// Already mmap-backed.  Unprotect so the caller can use it.
		if r.protected {
			r.protected = false
			poolGuardUnprotect(unsafe.Pointer(r.base), r.size)
		}
		return
	}

	// Not yet mmap-backed.  Migrate to a fresh mmap region.
	// Skip non-heap addresses (SRODATA, stacks, etc.)
	if !inheap(orig) {
		return
	}
	dataSize := uintptr(hdrCap) * elemSize
	newBase := poolGuardAllocPages(dataSize)
	if newBase == nil {
		return
	}
	memmove(newBase, *hdrData, dataSize)
	pageSize := (dataSize + physPageSize - 1) &^ (physPageSize - 1)
	poolGuardAddKnown(uintptr(newBase), pageSize)
	// Redirect the slice header so the caller and all future aliases it
	// creates point into the guarded mmap region.
	*hdrData = newBase
}

// poolGuardPutBacking protects the mmap-backed slice field at hdrData.
// By the time Put is called, the backing array must already be mmap-backed
// (set up by poolGuardGetBacking on the preceding Get call).  If not — e.g.
// a freshly-allocated item is Put without a prior Get — migrate it first.
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
	if poolGuardSuppressed(putPCs[:nPCs]) {
		return
	}

	r := poolGuardLookup(orig)
	if r == nil {
		// Not yet mmap-backed (Put without a prior Get, e.g. a freshly
		// allocated item).  Migrate to mmap now so we can protect it.
		// Only skip addresses that are neither Go heap nor our own mmap.
		if !inheap(orig) {
			return // SRODATA, stack, or other non-heap non-mmap address
		}
		newBase := poolGuardAllocPages(dataSize)
		if newBase == nil {
			return
		}
		memmove(newBase, *hdrData, dataSize)
		pageSize := (dataSize + physPageSize - 1) &^ (physPageSize - 1)
		r = poolGuardAddKnown(uintptr(newBase), pageSize)
		*hdrData = newBase
	}

	// Store the Put call stack for the fault report.
	r.nPCs = copy(r.putPCs[:], putPCs[:nPCs])
	r.protected = true

	// Delegate to platform-specific protection (mprotect or userfaultfd).
	poolGuardProtect(unsafe.Pointer(r.base), r.size, r)
}

// sliceHeader mirrors the slice header layout.  Used to read/write Data
// without triggering checkptr (same pattern as in sync/pool.go).
type pgSliceHeader struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

// poolGuardCanMigrate reports whether a slice with the given element type can
// safely be migrated to mmap pages.  Only slices whose elements contain no
// Go pointers (PtrBytes == 0) are eligible: migrating pointer-containing
// slices would hide those pointers from the GC, causing premature collection.
func poolGuardCanMigrate(elemTyp *abi.Type) bool {
	return elemTyp.PtrBytes == 0
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
			sliceTyp := (*abi.SliceType)(unsafe.Pointer(f.Typ))
			if !poolGuardCanMigrate(sliceTyp.Elem) {
				continue // element type contains Go pointers — skip to preserve GC safety
			}
			// Accept our own mmap-backed pages (not in Go heap) as well as
			// regular heap allocations.  Only skip truly non-addressable
			// regions (SRODATA etc.) that are neither heap nor our own mmap.
			data := uintptr(hdr.Data)
			if !inheap(data) && poolGuardLookup(data) == nil {
				continue
			}
			elemSize := sliceTyp.Elem.Size_
			if elemSize == 0 {
				continue
			}
			poolGuardPutBacking(&hdr.Data, hdr.Cap, elemSize)
		case abi.Struct:
			poolGuardPutSliceFields(fieldPtr, f.Typ)
		}
	}
}

// poolGuardGetSliceFields migrates or unprotects all slice backing arrays within base.
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
			if hdr.Cap == 0 {
				continue
			}
			sliceTyp := (*abi.SliceType)(unsafe.Pointer(f.Typ))
			if !poolGuardCanMigrate(sliceTyp.Elem) {
				continue
			}
			elemSize := sliceTyp.Elem.Size_
			if elemSize == 0 {
				continue
			}
			poolGuardGetBacking(&hdr.Data, hdr.Cap, elemSize)
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
		sliceTyp := (*abi.SliceType)(unsafe.Pointer(typ))
		if !poolGuardCanMigrate(sliceTyp.Elem) {
			return
		}
		elemSize := sliceTyp.Elem.Size_
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
// It migrates heap-backed slice fields to mmap pages (first call) or
// unprotects already-mmap-backed pages (subsequent calls).
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
		if hdr.Cap == 0 {
			return
		}
		sliceTyp := (*abi.SliceType)(unsafe.Pointer(typ))
		if !poolGuardCanMigrate(sliceTyp.Elem) {
			return
		}
		elemSize := sliceTyp.Elem.Size_
		if elemSize == 0 {
			return
		}
		poolGuardGetBacking(&hdr.Data, hdr.Cap, elemSize)
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
