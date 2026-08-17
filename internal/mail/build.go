package mail

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"
)

// Build assembles an RFC 5322 message.
//
// Headers are written here rather than by a library so their order and exact
// form are known: DKIM signs headers, and a header rewritten after signing
// invalidates the signature.
type Envelope struct {
	MessageID string
	From      string
	To        []string
	Subject   string
	HTML      string
	Text      string
	ReplyTo   string
	Extra     map[string]string
	Date      time.Time
}

func Build(e Envelope) ([]byte, error) {
	if err := ValidateSubject(e.Subject); err != nil {
		return nil, err
	}
	if len(e.To) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	var buf bytes.Buffer
	write := func(name, value string) error {
		if ContainsControl(value) {
			return fmt.Errorf("%s: %w", name, ErrControlCharacter)
		}
		fmt.Fprintf(&buf, "%s: %s\r\n", name, value)
		return nil
	}

	date := e.Date
	if date.IsZero() {
		date = time.Now()
	}

	// Khmer and other non-ASCII subjects are encoded per RFC 2047 so the
	// header stays 7-bit clean while the text survives intact.
	if err := write("From", e.From); err != nil {
		return nil, err
	}
	if err := write("To", strings.Join(e.To, ", ")); err != nil {
		return nil, err
	}
	if e.ReplyTo != "" {
		if err := write("Reply-To", e.ReplyTo); err != nil {
			return nil, err
		}
	}
	if err := write("Subject", mime.QEncoding.Encode("utf-8", e.Subject)); err != nil {
		return nil, err
	}
	if err := write("Message-ID", "<"+e.MessageID+">"); err != nil {
		return nil, err
	}
	if err := write("Date", date.Format(time.RFC1123Z)); err != nil {
		return nil, err
	}
	if err := write("MIME-Version", "1.0"); err != nil {
		return nil, err
	}
	for name, value := range e.Extra {
		if err := ValidateCustomHeader(name, value); err != nil {
			return nil, err
		}
		if err := write(name, value); err != nil {
			return nil, err
		}
	}

	text := e.Text
	if strings.TrimSpace(text) == "" {
		text = PlainTextFrom(e.HTML)
	}

	// A message with both parts is what mailbox providers expect; HTML-only
	// mail is a spam signal.
	if strings.TrimSpace(e.HTML) == "" {
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		buf.WriteString(quotedPrintable(text))
		return buf.Bytes(), nil
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	textPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, fmt.Errorf("building text part: %w", err)
	}
	if _, err := textPart.Write([]byte(quotedPrintable(text))); err != nil {
		return nil, fmt.Errorf("writing text part: %w", err)
	}

	htmlPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/html; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, fmt.Errorf("building html part: %w", err)
	}
	if _, err := htmlPart.Write([]byte(quotedPrintable(e.HTML))); err != nil {
		return nil, fmt.Errorf("writing html part: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("closing message: %w", err)
	}

	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", mw.Boundary())
	buf.Write(body.Bytes())
	return buf.Bytes(), nil
}

// PlainTextFrom derives a readable alternative from HTML. It is deliberately
// simple: the goal is a usable fallback, not a renderer.
func PlainTextFrom(html string) string {
	var out strings.Builder
	var inTag bool
	for _, r := range html {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			out.WriteRune(' ')
		case !inTag:
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(out.String()), " "))
}

func quotedPrintable(s string) string {
	var out bytes.Buffer
	w := newQPWriter(&out)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return out.String()
}
