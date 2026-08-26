package handler

import (
	"github.com/nsmithuk/local-kms/src/data"
)

type grantConstraints struct {
	EncryptionContextEquals map[string]string `json:",omitempty"`
	EncryptionContextSubset map[string]string `json:",omitempty"`
	SourceArn               string            `json:",omitempty"`
}

type grantListEntry struct {
	GrantId                  string
	Name                     string `json:",omitempty"`
	KeyId                    string
	GranteePrincipal         string `json:",omitempty"`
	GranteeServicePrincipal  string `json:",omitempty"`
	RetiringPrincipal        string `json:",omitempty"`
	RetiringServicePrincipal string `json:",omitempty"`
	Operations               []string
	Constraints              *grantConstraints `json:",omitempty"`
	CreationDate             float64
}

func newGrantListEntry(g *data.Grant) *grantListEntry {
	entry := &grantListEntry{
		GrantId:                  g.GrantId,
		Name:                     g.Name,
		KeyId:                    g.KeyArn,
		GranteePrincipal:         g.GranteePrincipal,
		GranteeServicePrincipal:  g.GranteeServicePrincipal,
		RetiringPrincipal:        g.RetiringPrincipal,
		RetiringServicePrincipal: g.RetiringServicePrincipal,
		Operations:               g.Operations,
		CreationDate:             g.CreationDate,
	}

	if g.Constraints != nil {
		entry.Constraints = &grantConstraints{
			EncryptionContextEquals: g.Constraints.EncryptionContextEquals,
			EncryptionContextSubset: g.Constraints.EncryptionContextSubset,
			SourceArn:               g.Constraints.SourceArn,
		}
	}

	return entry
}
