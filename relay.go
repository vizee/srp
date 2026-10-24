package main

import (
	"io"
	"net"
)

// pipe 在正常 EOF 时只关闭 dst 的写端，使反向数据仍可继续传输。
// 传输失败时关闭两端，唤醒另一方向的转发协程。
func pipe(dst net.Conn, src net.Conn) error {
	_, err := io.Copy(dst, src)
	if err == io.EOF {
		err = nil
	}
	if err == nil {
		if conn, ok := dst.(interface{ CloseWrite() error }); ok {
			err = conn.CloseWrite()
		} else {
			err = dst.Close()
		}
	}
	if err != nil {
		dst.Close()
		src.Close()
	}
	return err
}

// relay 负责双向转发，并在两个方向结束后关闭连接。
// preRead 是已从 src 读取的数据，必须先于后续数据写入 dst。
func relay(dst net.Conn, src net.Conn, preRead []byte) {
	defer dst.Close()
	defer src.Close()
	done := make(chan struct{})
	go func() {
		pipe(src, dst)
		close(done)
	}()

	if len(preRead) > 0 {
		if _, err := dst.Write(preRead); err != nil {
			dprintf("link established, send pre-read failed: %v", err)
			dst.Close()
			src.Close()
			<-done
			return
		}
	}
	pipe(dst, src)
	<-done
}
