package data

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func (d *Database) SaveKey(k cmk.Key) error {
	// Validate the key data before writing to prevent corruption
	if err := ValidateKeyData(k); err != nil {
		return err
	}

	encoded, err := json.Marshal(k)
	if err != nil {
		return err
	}

	return d.put([]byte(k.GetArn()), encoded)
}

func (d *Database) LoadKey(arn string) (cmk.Key, error) {

	encoded, err := d.database.Get([]byte(arn), nil)

	if err != nil {
		return nil, err
	}

	//---

	key, err := unmarshalKey(encoded)
	if err != nil {
		// Log the corruption error with the key ARN for debugging
		return nil, fmt.Errorf("failed to unmarshal key at %s, possible data corruption: %w", arn, err)
	}

	//---

	switch k := key.(type) {
	case *cmk.AesKey:
		if rotated := k.RotateIfNeeded(); rotated {
			if err := d.SaveKey(k); err != nil {
				return nil, err
			}
		}
	case *cmk.EccKey, *cmk.RsaKey:
		// no rotation needed
	default:
		return nil, errors.New("key type not supported")
	}

	//---

	// Migrate old keys to new naming
	if key.GetMetadata().KeySpec == "" {
		key.GetMetadata().KeySpec = key.GetMetadata().CustomerMasterKeySpec
	}

	//---

	if key.GetMetadata().IsPendingDeletion() {
		if err := d.DeleteObject(arn); err != nil {
			return nil, err
		}
		return nil, leveldb.ErrNotFound
	}

	// Reset key to pending import if key material has expired
	if key.GetMetadata().ValidTo != 0 && key.GetMetadata().ValidTo < float64(time.Now().Unix()) {
		key.GetMetadata().Enabled = false
		key.GetMetadata().KeyState = cmk.KeyStatePendingImport
		key.GetMetadata().ExpirationModel = ""
		key.GetMetadata().ValidTo = 0
		if err := d.SaveKey(key); err != nil {
			return nil, err
		}
	}

	//---

	return key, err
}

/*
Returns all keys.

	If limit is set, only that given number of keys are returned.
	If marker is set, only key with match, and come after, the marker key are returned. i.e. an 'offset'.
*/
func (d *Database) ListKeys(prefix string, limit int64, marker string) (keys []cmk.Key, err error) {

	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix)), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// Exclude tags
		if strings.Contains(string(iter.Key()), "/tag/") {
			continue
		}

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		if marker != "" && !pastMarker && marker != string(iter.Key()) {
			continue
		}

		pastMarker = true

		key, err := unmarshalKey(iter.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal key at %s, possible data corruption: %w", string(iter.Key()), err)
		}

		if key.GetMetadata().IsPendingDeletion() {
			if err := d.DeleteObject(key.GetArn()); err != nil {
				continue
			}
			continue
		}

		keys = append(keys, key)

		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
}

func unmarshalKey(encoded []byte) (cmk.Key, error) {

	//---------------------------------------------------------
	// Unmarshal just the key's type

	var kt struct {
		Type cmk.KeyType
	}

	err := json.Unmarshal(encoded, &kt)
	if err != nil {
		return nil, err
	}

	//---------------------------------------------------------
	// Unmarshal the full key, with the correct Implementation

	var key cmk.Key

	// If no key type has been set, the value of kt.Type will be 0 (an empty int).
	// Therefore no key type being set will default to an AesKey.
	// This is the desired behaviour for backwards compatibility.

	switch kt.Type {
	case cmk.TypeAes:
		key = new(cmk.AesKey)
	case cmk.TypeEcc:
		key = new(cmk.EccKey)
	case cmk.TypeRsa:
		key = new(cmk.RsaKey)
	default:
		return nil, errors.New("key type not yet supported")
	}

	err = json.Unmarshal(encoded, &key)

	return key, err
}
