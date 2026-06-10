package data

import (
	"encoding/json"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func (d *Database) SaveAlias(a *Alias) error {
	// Validate the alias data before writing to prevent corruption
	if err := ValidateAliasData(a); err != nil {
		return err
	}

	encoded, err := json.Marshal(a)
	if err != nil {
		return err
	}

	return d.put([]byte(a.AliasArn), encoded)
}

func (d *Database) LoadAlias(arn string) (*Alias, error) {
	var a Alias

	encoded, err := d.database.Get([]byte(arn), nil)

	if err != nil {
		return nil, err
	}

	//---

	if err := json.Unmarshal(encoded, &a); err != nil {
		// Return detailed error for corruption detection
		return nil, fmt.Errorf("failed to unmarshal alias at %s, possible data corruption: %w", arn, err)
	}

	return &a, nil
}

func (d *Database) ListAlias(prefix string, limit int64, marker, key string) (aliases []*Alias, err error) {

	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix)), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		if marker != "" && !pastMarker && marker != string(iter.Key()) {
			continue
		}

		pastMarker = true

		var a Alias

		if err = json.Unmarshal(iter.Value(), &a); err != nil {
			err = fmt.Errorf("failed to unmarshal alias at %s, possible data corruption: %w", string(iter.Key()), err)
			return
		}

		if key != "" && a.TargetKeyId != key {
			// If we're filtering by key, skip entry if the key doesn't match.
			continue
		}

		aliases = append(aliases, &a)

		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
}
