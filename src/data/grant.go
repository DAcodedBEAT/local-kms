package data

type GrantConstraints struct {
	EncryptionContextEquals map[string]string `json:",omitempty"`
	EncryptionContextSubset map[string]string `json:",omitempty"`
	SourceArn               string            `json:",omitempty"`
}

type Grant struct {
	GrantId                  string
	GrantToken               string
	Name                     string
	KeyArn                   string
	GranteePrincipal         string
	GranteeServicePrincipal  string
	RetiringPrincipal        string
	RetiringServicePrincipal string
	Operations               []string
	Constraints              *GrantConstraints `json:",omitempty"`
	CreationDate             float64
}
