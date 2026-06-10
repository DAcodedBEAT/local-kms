package data

import (
	"fmt"
	"os"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// syncWrite forces fsync on every Put/Delete so key material is durable before
// the handler returns a success response to the caller.
var syncWrite = &opt.WriteOptions{Sync: true}

type Database struct {
	database *leveldb.DB
	dbPath   string
}

func NewDatabase(path string) *Database {

	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: failed to open database at %s (%v); attempting recovery\n", path, err)
		db, err = leveldb.RecoverFile(path, nil)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "WARN: database at %s recovered from corrupted state\n", path)
	}

	return &Database{
		database: db,
		dbPath:   path,
	}
}

func (d *Database) Close() error {
	return d.database.Close()
}

//------------------------------------

type InvalidMarkerExceptionError struct{}

func (e *InvalidMarkerExceptionError) Error() string {
	return "Invalid marker"
}

//------------------------------------

// Can delete any object type. e.g. key, alias, etc.
func (d *Database) DeleteObject(arn string) error {
	// Check available disk space before writing (deletes also require space for compaction)
	if err := CheckDiskSpace(d.dbPath); err != nil {
		return err
	}

	return d.database.Delete([]byte(arn), syncWrite)
}
