// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package race_test

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestRacePool(t *testing.T) {
	// Pool randomly drops the argument on the floor during Put.
	// Repeat so that at least one iteration gets reuse.
	for i := 0; i < 10; i++ {
		c := make(chan int)
		p := &sync.Pool{New: func() any { return make([]byte, 10) }}
		x := p.Get().([]byte)
		x[0] = 1
		p.Put(x)
		go func() {
			y := p.Get().([]byte)
			y[0] = 2
			c <- 1
		}()
		x[0] = 3
		<-c
	}
}

func TestNoRacePool(t *testing.T) {
	for i := 0; i < 10; i++ {
		p := &sync.Pool{New: func() any { return make([]byte, 10) }}
		x := p.Get().([]byte)
		x[0] = 1
		p.Put(x)
		go func() {
			y := p.Get().([]byte)
			y[0] = 2
			p.Put(y)
		}()
		time.Sleep(100 * time.Millisecond)
		x = p.Get().([]byte)
		x[0] = 3
	}
}

// TestRaceFailingPoolPutUseSameGoroutine checks that a write to a pool object
// after Put in the same goroutine is detected as use-after-pool-put.
// Marked Failing because quarantine detection requires a TSan .syso update.
func TestRaceFailingPoolPutUseSameGoroutine(t *testing.T) {
	p := &sync.Pool{New: func() any { return new(bytes.Buffer) }}
	for i := 0; i < 10; i++ {
		buf := p.Get().(*bytes.Buffer)
		buf.Reset()
		p.Put(buf)
		buf.WriteByte('x') // BUG: use after Put
	}
}

// TestRaceFailingPoolPutUseCrossGoroutine checks that a cross-goroutine write
// to a pool object after Put is detected.
// Marked Failing because quarantine detection requires a TSan .syso update.
func TestRaceFailingPoolPutUseCrossGoroutine(t *testing.T) {
	p := &sync.Pool{New: func() any { return new(bytes.Buffer) }}
	for i := 0; i < 10; i++ {
		buf := p.Get().(*bytes.Buffer)
		buf.Reset()
		p.Put(buf)
		done := make(chan struct{})
		go func() {
			buf.WriteByte('x') // BUG: concurrent write after Put
			close(done)
		}()
		<-done
	}
}

// TestNoRacePoolPutGet verifies that the normal Put→Get→use cycle is clean.
func TestNoRacePoolPutGet(t *testing.T) {
	p := &sync.Pool{New: func() any { return new(bytes.Buffer) }}
	for i := 0; i < 10; i++ {
		buf := p.Get().(*bytes.Buffer)
		buf.Reset()
		p.Put(buf)
		buf2 := p.Get().(*bytes.Buffer) // may or may not be same object
		buf2.WriteByte('x')             // safe: acquired from pool
		p.Put(buf2)
	}
}

// TestNoRacePoolNew verifies that using an object returned by Pool.New is clean.
func TestNoRacePoolNew(t *testing.T) {
	p := &sync.Pool{New: func() any { return new(bytes.Buffer) }}
	buf := p.Get().(*bytes.Buffer) // always from New the first time
	buf.WriteByte('x')             // safe: fresh allocation, never Put
	_ = buf
}
