package mail

import (
	"io"
	"mime/quotedprintable"
)

func newQPWriter(w io.Writer) io.WriteCloser {
	return quotedprintable.NewWriter(w)
}
