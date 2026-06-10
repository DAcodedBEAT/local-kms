package data

import (
	"encoding/json"
	"fmt"

	"github.com/nsmithuk/local-kms/src/cmk"
)

// ValidateKeyData verifies that a key object can be properly serialized and deserialized,
// and that AES keys have backing key material before being persisted.
func ValidateKeyData(k cmk.Key) error {
	// AES keys without backing keys cannot decrypt — catch this before persisting.
	if aesKey, ok := k.(*cmk.AesKey); ok {
		if aesKey.Metadata.Origin != cmk.KeyOriginExternal && len(aesKey.BackingKeys) == 0 {
			return fmt.Errorf("AES key %s has no backing keys; refusing to save", k.GetArn())
		}
	}

	encoded, err := json.Marshal(k)
	if err != nil {
		return fmt.Errorf("failed to marshal key for validation: %w", err)
	}

	if _, err := unmarshalKey(encoded); err != nil {
		return fmt.Errorf("failed to unmarshal key for validation: %w", err)
	}

	return nil
}

// ValidateAliasData verifies that an alias object can be properly serialized and deserialized
func ValidateAliasData(a *Alias) error {
	// Serialize the alias
	encoded, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("failed to marshal alias for validation: %w", err)
	}

	// Attempt to deserialize it to verify integrity
	var validationAlias Alias
	if err := json.Unmarshal(encoded, &validationAlias); err != nil {
		return fmt.Errorf("failed to unmarshal alias for validation: %w", err)
	}

	return nil
}

// ValidateTagData verifies that a tag object can be properly serialized and deserialized
func ValidateTagData(t *Tag) error {
	// Serialize the tag
	encoded, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("failed to marshal tag for validation: %w", err)
	}

	// Attempt to deserialize it to verify integrity
	var validationTag Tag
	if err := json.Unmarshal(encoded, &validationTag); err != nil {
		return fmt.Errorf("failed to unmarshal tag for validation: %w", err)
	}

	return nil
}
