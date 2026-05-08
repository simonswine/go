// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && (darwin || dragonfly || freebsd || illumos || netbsd || openbsd || solaris)

package runtime

import "unsafe"

// Non-Linux pool guard: uses mprotect(PROT_NONE) to make pages inaccessible.
// Any access fires a SIGSEGV that is caught by sigpanic and reported via
// poolGuardReport before throwing.

func poolGuardProtect(addr unsafe.Pointer, size uintptr, _ *poolGuardPage) {
	mprotect(addr, size, _PROT_NONE)
}

func poolGuardUnprotect(addr unsafe.Pointer, size uintptr) {
	mprotect(addr, size, _PROT_READ|_PROT_WRITE)
}
