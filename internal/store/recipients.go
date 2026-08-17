package store

import (
	"encoding/json"
	"fmt"
)

// packRecipients returns the ciphertext and lookup hashes for a recipient
// list. Hashes are stored alongside so a query never needs the plaintext.
func (s *Store) packRecipients(recipients []string) (encrypted []byte, hashes [][]byte, clear []string, err error) {
	for _, r := range recipients {
		hashes = append(hashes, SuppressionHash(r))
	}

	if s.keeper == nil {
		// No master key: behave as before rather than refusing to run. A
		// deployment that can send always has one, because sending requires it.
		return nil, hashes, recipients, nil
	}

	payload, err := json.Marshal(recipients)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encoding recipients: %w", err)
	}
	encrypted, err = s.keeper.Wrap(payload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encrypting recipients: %w", err)
	}
	return encrypted, hashes, nil, nil
}

// unpackRecipients reads whichever form a row holds.
//
// Rows written before encryption keep their cleartext column until retention
// removes them, so both are supported on read and only one on write.
func (s *Store) unpackRecipients(encrypted []byte, clear []string) ([]string, error) {
	if len(encrypted) == 0 {
		return clear, nil
	}
	if s.keeper == nil {
		return nil, fmt.Errorf("recipients are encrypted but no master key is configured")
	}

	payload, err := s.keeper.Unwrap(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting recipients: %w", err)
	}
	var recipients []string
	if err := json.Unmarshal(payload, &recipients); err != nil {
		return nil, fmt.Errorf("decoding recipients: %w", err)
	}
	return recipients, nil
}
