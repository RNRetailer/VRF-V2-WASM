package vrfkey

import "github.com/RNRetailer/rng/go_eth/accounts/keystore"

// Copied from go-ethereum/accounts/keystore/key.go's encryptedKeyJSONV3
type gethKeyStruct struct {
	Address string              `json:"address"`
	Crypto  keystore.CryptoJSON `json:"crypto"`
	Version int                 `json:"version"`
}
