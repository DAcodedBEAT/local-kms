package data

import (
	"context"
	"log/slog"

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

func NewDatabase(ctx context.Context, path string) *Database {

	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		slog.Default().WarnContext(ctx, "database open failed, attempting recovery", "path", path, "error", err)
		db, err = leveldb.RecoverFile(path, nil)
		if err != nil {
			panic(err)
		}
		slog.Default().WarnContext(ctx, "database recovered from corrupted state", "path", path)
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
	if err := CheckDiskSpace(d.dbPath); err != nil {
		return err
	}
	return d.database.Delete([]byte(arn), syncWrite)
}

func (d *Database) put(key []byte, value []byte) error {
	if err := CheckDiskSpace(d.dbPath); err != nil {
		return err
	}
	return d.database.Put(key, value, syncWrite)
}
