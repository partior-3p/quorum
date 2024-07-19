package nodekey

type NodeKeyConfig struct {
	ConfigVault VaultConfig `toml:",omitempty"`
	ConfigFile  FileConfig  `toml:",omitempty"`
}

type FileConfig struct {
	Hex  string `toml:",omitempty"`
	File string `toml:",omitempty"`
}

type VaultConfig struct {
	Url                    string `toml:",omitempty"` // scheme + host + port
	KvVersion              string `toml:",omitempty"`
	KvMount                string `toml:",omitempty"`
	KvPath                 string `toml:",omitempty"`
	KvFetchKey             string `toml:",omitempty"` // key to retrieve data from
	TseMount               string `toml:",omitempty"`
	TseKeyName             string `toml:",omitempty"`
	Token                  string `toml:",omitempty"`
	AppRoleId              string `toml:",omitempty"`
	AppRoleSecret          string `toml:",omitempty"`
	AppRolePath            string `toml:",omitempty"`
	Namespace              string `toml:",omitempty"`
	VaultTlsServerCertPath string `toml:",omitempty"`
}
