package data

import (
	"encoding/json"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb/util"
)

const grantPrefix = "grant/"

func grantStorageKey(grantId string) string {
	return grantPrefix + grantId
}

func (d *Database) SaveGrant(g *Grant) error {
	if err := ValidateGrantData(g); err != nil {
		return err
	}

	encoded, err := json.Marshal(g)
	if err != nil {
		return err
	}

	return d.put([]byte(grantStorageKey(g.GrantId)), encoded)
}

func (d *Database) LoadGrant(grantId string) (*Grant, error) {
	var g Grant

	encoded, err := d.database.Get([]byte(grantStorageKey(grantId)), nil)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(encoded, &g); err != nil {
		return nil, fmt.Errorf("failed to unmarshal grant %s, possible data corruption: %w", grantId, err)
	}

	return &g, nil
}

func (d *Database) DeleteGrant(grantId string) error {
	return d.DeleteObject(grantStorageKey(grantId))
}

// FindGrantByToken scans all grants for one matching the given grant token.
func (d *Database) FindGrantByToken(token string) (*Grant, error) {
	iter := d.database.NewIterator(util.BytesPrefix([]byte(grantPrefix)), nil)
	defer iter.Release()

	for iter.Next() {
		var g Grant
		if err := json.Unmarshal(iter.Value(), &g); err != nil {
			return nil, fmt.Errorf("failed to unmarshal grant at %s, possible data corruption: %w", string(iter.Key()), err)
		}
		if g.GrantToken == token {
			return &g, nil
		}
	}

	if err := iter.Error(); err != nil {
		return nil, err
	}

	return nil, nil
}

// GrantFilter narrows a grant listing. Empty fields are not filtered on.
type GrantFilter struct {
	KeyArn                   string
	GrantId                  string
	GranteePrincipal         string
	GranteeServicePrincipal  string
	RetiringPrincipal        string
	RetiringServicePrincipal string
}

func (f GrantFilter) matches(g *Grant) bool {
	if f.KeyArn != "" && g.KeyArn != f.KeyArn {
		return false
	}
	if f.GrantId != "" && g.GrantId != f.GrantId {
		return false
	}
	if f.GranteePrincipal != "" && g.GranteePrincipal != f.GranteePrincipal {
		return false
	}
	if f.GranteeServicePrincipal != "" && g.GranteeServicePrincipal != f.GranteeServicePrincipal {
		return false
	}
	if f.RetiringPrincipal != "" && g.RetiringPrincipal != f.RetiringPrincipal {
		return false
	}
	if f.RetiringServicePrincipal != "" && g.RetiringServicePrincipal != f.RetiringServicePrincipal {
		return false
	}
	return true
}

// ListGrants returns, in storage order, up to limit grants matching filter,
// starting after marker (a grant ID) if provided.
func (d *Database) ListGrants(filter GrantFilter, limit int64, marker string) (grants []*Grant, err error) {
	return d.scanGrants(limit, marker, filter.matches)
}

func (d *Database) scanGrants(limit int64, marker string, include func(*Grant) bool) (grants []*Grant, err error) {
	iter := d.database.NewIterator(util.BytesPrefix([]byte(grantPrefix)), nil)

	var count int64
	pastMarker := false
	markerKey := ""
	if marker != "" {
		markerKey = grantStorageKey(marker)
	}

	for count < limit && iter.Next() {

		if markerKey != "" && !pastMarker && markerKey != string(iter.Key()) {
			continue
		}
		pastMarker = true

		var g Grant
		if err = json.Unmarshal(iter.Value(), &g); err != nil {
			err = fmt.Errorf("failed to unmarshal grant at %s, possible data corruption: %w", string(iter.Key()), err)
			iter.Release()
			return
		}

		if !include(&g) {
			continue
		}

		grants = append(grants, &g)
		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
}
