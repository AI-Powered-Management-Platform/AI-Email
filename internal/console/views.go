package console

import (
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

// The view types keep formatting out of templates, and keep the raw rows out
// of the page: a field that is never mapped here can never be rendered.

type domainView struct {
	Name          string
	Status        string
	Token         string
	DKIMSelector  string
	DKIMRecord    string
	LastCheckedAt string
}

func newDomainView(d store.DomainRow) domainView {
	return domainView{
		Name:          d.Name,
		Status:        d.Status,
		Token:         d.Token,
		DKIMSelector:  d.DKIMSelector,
		DKIMRecord:    d.DKIMRecord,
		LastCheckedAt: formatTime(d.LastCheckedAt),
	}
}

type keyView struct {
	ID         int64
	Name       string
	Prefix     string
	Scopes     []string
	Quota      int
	ExpiresAt  string
	RevokedAt  string
	Expired    bool
	LastUsedAt string
	LastUsedIP string
}

func newKeyView(k store.KeyRow) keyView {
	v := keyView{
		ID:         k.ID,
		Name:       k.Name,
		Prefix:     k.Prefix,
		Scopes:     k.Scopes,
		Quota:      k.Quota,
		ExpiresAt:  k.ExpiresAt.UTC().Format("2006-01-02"),
		Expired:    !time.Now().Before(k.ExpiresAt),
		LastUsedAt: formatTime(k.LastUsedAt),
	}
	if k.RevokedAt != nil {
		v.RevokedAt = formatTime(k.RevokedAt)
	}
	if k.LastUsedIP != nil {
		v.LastUsedIP = *k.LastUsedIP
	}
	return v
}

type messageView struct {
	ID         string
	Status     string
	Recipients []string
	Subject    string
	Attempts   int
	LastError  string
	SignedAt   string
	CreatedAt  string
}

func newMessageView(m store.MessageRow) messageView {
	v := messageView{
		ID:         m.ID,
		Status:     m.Status,
		Recipients: m.Recipients,
		Subject:    m.Subject,
		Attempts:   m.Attempts,
		SignedAt:   formatTime(m.SignedAt),
		CreatedAt:  m.CreatedAt.UTC().Format("2006-01-02 15:04"),
	}
	if m.LastError != nil {
		v.LastError = *m.LastError
	}
	return v
}

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04")
}
