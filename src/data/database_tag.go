package data

import (
	"encoding/json"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func (d *Database) SaveTag(k cmk.Key, t *Tag) error {
	// Check available disk space before writing
	if err := CheckDiskSpace(d.dbPath); err != nil {
		return err
	}

	// Validate the tag data before writing to prevent corruption
	if err := ValidateTagData(t); err != nil {
		return err
	}

	encoded, err := json.Marshal(t)
	if err != nil {
		return err
	}

	// We save under a value of the key's ARN, plus the tag key value.
	return d.database.Put([]byte(k.GetArn()+"/tag/"+t.TagKey), encoded, syncWrite)
}

// CountTags returns the number of tags stored for the given key ARN.
func (d *Database) CountTags(keyArn string) (int, error) {
	iter := d.database.NewIterator(util.BytesPrefix([]byte(keyArn+"/tag")), nil)
	defer iter.Release()
	count := 0
	for iter.Next() {
		count++
	}
	return count, iter.Error()
}

func (d *Database) ListTags(prefix string, limit int64, marker string) (tags []*Tag, err error) {

	// The prefix is the Key's ARN, plus /tag
	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix+"/tag")), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		// The marker needs the Key ARN and /tag/ including
		if marker != "" && !pastMarker && prefix+"/tag/"+marker != string(iter.Key()) {
			continue
		}

		pastMarker = true

		var t Tag

		err = json.Unmarshal(iter.Value(), &t)
		if err != nil {
			return
		}

		tags = append(tags, &t)

		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
}
