package src

import (
	"context"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/syndtr/goleveldb/leveldb"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
)

func seed(ctx context.Context, path string, database *data.Database) {

	if path == "" {
		logger.InfoContext(ctx, "No seed path, skipping seeding")
		return
	}

	path, _ = filepath.Abs(path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.InfoContext(ctx, "No seed file found, skipping", "path", path)
		return
	}

	fileContent, err := os.ReadFile(path)
	if err != nil {
		logger.ErrorContext(ctx, "Unable to read seed file", "path", path, "error", err)
		return
	}

	//---

	type InputSymmetric struct {
		Aes []cmk.AesKey `yaml:"Aes"`
	}
	type InputAsymmetric struct {
		Rsa []cmk.RsaKey `yaml:"Rsa"`
		Ecc []cmk.EccKey `yaml:"Ecc"`
	}

	type InputKeys struct {
		Symmetric  InputSymmetric  `yaml:"Symmetric"`
		Asymmetric InputAsymmetric `yaml:"Asymmetric"`
	}

	type Input struct {
		Keys    InputKeys    `yaml:"Keys"`
		Aliases []data.Alias `yaml:"Aliases"`
	}

	seed := Input{}

	var eccKeys []cmk.EccKey
	var rsaKeys []cmk.RsaKey
	var aesKeys []cmk.AesKey
	var aliases []data.Alias

	err = yaml.Unmarshal(fileContent, &seed)
	if err != nil {

		logger.WarnContext(ctx, "YAML parse error, attempting legacy format", "path", path, "error", err)

		//------------------------------------------------------
		// Try processing the document in the legacy format

		// TODO Support for the legacy format will be removed in future versions.

		type InputOld struct {
			Keys    []cmk.AesKey `yaml:"Keys"`
			Aliases []data.Alias `yaml:"Aliases"`
		}

		seed := InputOld{}
		err = yaml.Unmarshal(fileContent, &seed)
		if err != nil {
			logger.ErrorContext(ctx, "YAML parse error", "path", path, "error", err)
			return
		}

		if len(seed.Keys) > 0 {
			logger.WarnContext(ctx, "Legacy seed format detected, will be removed in a future version")
		}

		aesKeys = append(aesKeys, seed.Keys...)

		aliases = append(aliases, seed.Aliases...)

		//------------------------------------------------------

	} else {
		aesKeys = append(aesKeys, seed.Keys.Symmetric.Aes...)
		rsaKeys = append(rsaKeys, seed.Keys.Asymmetric.Rsa...)
		eccKeys = append(eccKeys, seed.Keys.Asymmetric.Ecc...)
		aliases = append(aliases, seed.Aliases...)
	}

	logger.InfoContext(ctx, "Importing seed data", "path", path)

	for i, alias := range aliases {
		aliases[i].AliasArn = config.ArnPrefix() + alias.AliasName
	}

	//-----------------------------------------
	// Save to database

	keysAdded := 0
	for _, key := range aesKeys {
		if keyIsNew(ctx, database, &key.Metadata) {
			if err := database.SaveKey(&key); err != nil {
				logger.WarnContext(ctx, "Failed to save key", "keyId", key.GetMetadata().KeyId, "error", err)
				continue
			}
			keysAdded++
		}
	}
	for _, key := range rsaKeys {
		if keyIsNew(ctx, database, &key.Metadata) {
			if err := database.SaveKey(&key); err != nil {
				logger.WarnContext(ctx, "Failed to save key", "keyId", key.GetMetadata().KeyId, "error", err)
				continue
			}
			keysAdded++
		}
	}
	for _, key := range eccKeys {
		if keyIsNew(ctx, database, &key.Metadata) {
			if err := database.SaveKey(&key); err != nil {
				logger.WarnContext(ctx, "Failed to save key", "keyId", key.GetMetadata().KeyId, "error", err)
				continue
			}
			keysAdded++
		}
	}

	aliasesAdded := 0
	for _, alias := range aliases {

		if _, err := database.LoadAlias(alias.AliasArn); err != leveldb.ErrNotFound {
			logger.WarnContext(ctx, "Alias already exists, skipping", "aliasName", alias.AliasName)
			continue
		}

		if err := database.SaveAlias(&alias); err != nil {
			logger.WarnContext(ctx, "Failed to save alias", "aliasName", alias.AliasName, "error", err)
			continue
		}
		aliasesAdded++
	}

	logger.InfoContext(ctx, "Seed complete", "keysAdded", keysAdded, "aliasesAdded", aliasesAdded)
}

func keyIsNew(ctx context.Context, database *data.Database, metadata *cmk.KeyMetadata) bool {
	if _, err := database.LoadKey(metadata.Arn); err != leveldb.ErrNotFound {
		logger.WarnContext(ctx, "Key already exists, skipping", "keyId", metadata.KeyId)
		return false
	}
	return true
}
