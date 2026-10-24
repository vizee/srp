// Package transport owns TCP connections and copies bidirectional byte streams.
package transport

import (
	"context"
	"io"
	"net"
)

func Bridge(ctx context.Context, a, b net.Conn) {
	closeBoth := func() { a.Close(); b.Close() }
	defer closeBoth()
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(dst, src)
		if err == nil {
			if c, ok := dst.(interface{ CloseWrite() error }); ok {
				err = c.CloseWrite()
			} else {
				err = dst.Close()
			}
		}
		if err != nil {
			closeBoth()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
}
