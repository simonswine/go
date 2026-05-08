// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package runtime

import (
	"internal/runtime/syscall/linux"
	"unsafe"
)

// Linux pool guard: uses userfaultfd + madvise(MADV_DONTNEED) so that
// access to quarantined pool pages is intercepted by a background goroutine
// rather than crashing with SIGSEGV.  The faulting goroutine is paused while
// the handler prints full context, then resumes with a zero-filled page.
//
// If userfaultfd is not available (kernel < 4.3 or permission denied), we fall
// back to mprotect(PROT_NONE) + SIGSEGV handling in sigpanic.

// poolGuardUFFD is the global userfaultfd file descriptor, or -1 if unavailable.
var poolGuardUFFD int32 = -1

// poolGuardUFFDReady is set to true after the background goroutine starts.
var poolGuardUFFDReady bool

// uffd ioctl constants (from linux/userfaultfd.h).
// Computed as _IOWR(0xAA, nr, sizeof(struct)) / _IOR(0xAA, nr, sizeof(struct)).
const (
	_UFFDIO_API        = 0xc018aa3f // _IOWR(0xAA, 0x3F, 24)
	_UFFDIO_REGISTER   = 0xc020aa00 // _IOWR(0xAA, 0x00, 32)
	_UFFDIO_UNREGISTER = 0x8010aa01 // _IOR (0xAA, 0x01, 16)
	_UFFDIO_ZEROPAGE   = 0xc020aa02 // _IOWR(0xAA, 0x02, 32)

	_UFFDIO_REGISTER_MODE_MISSING = 1 << 0

	_UFFD_EVENT_PAGEFAULT = 0x12

	_UFFD_API = 0xaa
)

// uffdioAPI matches struct uffdio_api (24 bytes).
type uffdioAPI struct {
	api      uint64
	features uint64
	ioctls   uint64
}

// uffdioRange matches struct uffdio_range (16 bytes).
type uffdioRange struct {
	start uint64
	len_  uint64
}

// uffdioRegister matches struct uffdio_register (32 bytes).
type uffdioRegister struct {
	rang   uffdioRange
	mode   uint64
	ioctls uint64
}

// uffdioZeropage matches struct uffdio_zeropage (32 bytes).
type uffdioZeropage struct {
	rang     uffdioRange
	mode     uint64
	zeropage int64
}

// uffdMsg matches struct uffd_msg (32 bytes, pagefault variant).
type uffdMsg struct {
	event     uint8
	reserved1 uint8
	reserved2 uint16
	reserved3 uint32
	flags     uint64 // pagefault.flags
	address   uint64 // pagefault.address
	ptid      uint32 // pagefault.feat.ptid
	_         uint32
}

func poolGuardInitOS() {
	// Open a userfaultfd file descriptor.
	fd, _, errno := linux.Syscall6(uintptr(linux.SYS_USERFAULTFD), 0, 0, 0, 0, 0, 0)
	if errno != 0 {
		// Kernel too old or permission denied; fall through to mprotect mode.
		return
	}
	// Negotiate API version.
	api := uffdioAPI{api: _UFFD_API}
	_, _, errno = linux.Syscall6(uintptr(linux.SYS_IOCTL), fd, _UFFDIO_API,
		uintptr(unsafe.Pointer(&api)), 0, 0, 0)
	if errno != 0 {
		linux.Syscall6(uintptr(linux.SYS_CLOSE), fd, 0, 0, 0, 0, 0)
		return
	}
	poolGuardUFFD = int32(fd)

	// Launch the background handler goroutine.
	go poolGuardUFFDHandler()
	poolGuardUFFDReady = true
}

// poolGuardUFFDHandler reads events from the userfaultfd and handles
// missing-page events for guarded pool pages.
func poolGuardUFFDHandler() {
	fd := uintptr(poolGuardUFFD)
	var msg uffdMsg
	msgSize := unsafe.Sizeof(msg)
	for {
		n, errno := linux.Read(int(fd), (*[unsafe.Sizeof(uffdMsg{})]byte)(unsafe.Pointer(&msg))[:msgSize])
		if errno != 0 || n == 0 {
			return // fd closed or error
		}
		if msg.event != _UFFD_EVENT_PAGEFAULT {
			continue
		}
		faultAddr := uintptr(msg.address)
		r := poolGuardFind(faultAddr)
		if r != nil {
			poolGuardPrintReport(r, faultAddr)
		}
		// Provide a zero page so the faulting goroutine can continue.
		pageBase := faultAddr &^ (physPageSize - 1)
		zp := uffdioZeropage{
			rang: uffdioRange{start: uint64(pageBase), len_: uint64(physPageSize)},
		}
		linux.Syscall6(uintptr(linux.SYS_IOCTL), fd, _UFFDIO_ZEROPAGE,
			uintptr(unsafe.Pointer(&zp)), 0, 0, 0)
		if r != nil {
			throw("use after Pool.Put")
		}
	}
}

// poolGuardPrintReport prints a detailed report.  Called from the userfaultfd
// handler goroutine so full Go facilities are available.
func poolGuardPrintReport(r *poolGuardPage, faultAddr uintptr) {
	print("\n==================\n")
	print("WARNING: accessed pool buffer after Pool.Put\n\n")
	print("Fault address: ", hex(faultAddr), "\n\n")
	print("Pool.Put call stack:\n")
	frames := CallersFrames(r.putPCs[:r.nPCs])
	for {
		frame, more := frames.Next()
		if frame.PC == 0 {
			break
		}
		print("  ", frame.Function, "\n\t", frame.File, ":", frame.Line, "\n")
		if !more {
			break
		}
	}
	print("==================\n\n")
}

func poolGuardRegisterUFFD(base, size uintptr) {
	if poolGuardUFFD < 0 {
		return
	}
	reg := uffdioRegister{
		rang: uffdioRange{start: uint64(base), len_: uint64(size)},
		mode: _UFFDIO_REGISTER_MODE_MISSING,
	}
	linux.Syscall6(uintptr(linux.SYS_IOCTL), uintptr(poolGuardUFFD), _UFFDIO_REGISTER,
		uintptr(unsafe.Pointer(&reg)), 0, 0, 0)
}

func poolGuardUnregisterUFFD(base, size uintptr) {
	if poolGuardUFFD < 0 {
		return
	}
	rang := uffdioRange{start: uint64(base), len_: uint64(size)}
	linux.Syscall6(uintptr(linux.SYS_IOCTL), uintptr(poolGuardUFFD), _UFFDIO_UNREGISTER,
		uintptr(unsafe.Pointer(&rang)), 0, 0, 0)
}

// poolGuardProtect makes the pages at [addr, addr+size) inaccessible.
// On Linux with userfaultfd: register + madvise(MADV_DONTNEED) so the
// handler goroutine intercepts the next access gracefully.
// Fallback: mprotect(PROT_NONE) for the SIGSEGV path.
func poolGuardProtect(addr unsafe.Pointer, size uintptr, _ *poolGuardPage) {
	if poolGuardUFFD >= 0 {
		// Register the range before dropping pages so no access slips through.
		poolGuardRegisterUFFD(uintptr(addr), size)
		madvise(addr, size, _MADV_DONTNEED)
	} else {
		mprotect(addr, size, _PROT_NONE)
	}
}

// poolGuardUnprotect restores access to pages at [addr, addr+size).
func poolGuardUnprotect(addr unsafe.Pointer, size uintptr) {
	if poolGuardUFFD >= 0 {
		poolGuardUnregisterUFFD(uintptr(addr), size)
		// Re-drop so the kernel zero-fills them on next access without UFFD.
		madvise(addr, size, _MADV_DONTNEED)
	} else {
		mprotect(addr, size, _PROT_READ|_PROT_WRITE)
	}
}

func init() {
	if debug.poolguard != 0 {
		poolGuardInitOS()
	}
}
