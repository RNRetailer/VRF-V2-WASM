package vrfkey

import (
	"encoding/json"

	"github.com/RNRetailer/rng/chainlink_develop/secp256k1"
	"github.com/RNRetailer/rng/cosmossdk/errors"
	"github.com/RNRetailer/rng/go_eth/accounts/keystore"

	"github.com/RNRetailer/rng/uuid"
)

type EncryptedVRFKeyExport struct {
	PublicKey secp256k1.PublicKey `json:"PublicKey"`
	VRFKey    gethKeyStruct       `json:"vrf_key"`
}

func FromEncryptedJSON(keyJSON []byte, password string) (KeyV2, error) {
	var export EncryptedVRFKeyExport
	if err := json.Unmarshal(keyJSON, &export); err != nil {
		return KeyV2{}, err
	}

	// NOTE: We do this shuffle to an anonymous struct
	// solely to add a throwaway UUID, so we can leverage
	// the keystore.DecryptKey from the geth which requires it
	// as of 1.10.0.
	keyJSON, err := json.Marshal(struct {
		Address string              `json:"address"`
		Crypto  keystore.CryptoJSON `json:"crypto"`
		Version int                 `json:"version"`
		Id      string              `json:"id"`
	}{
		Address: export.VRFKey.Address,
		Crypto:  export.VRFKey.Crypto,
		Version: export.VRFKey.Version,
		Id:      uuid.New().String(),
	})
	if err != nil {
		return KeyV2{}, errors.Wrapf(err, "while marshaling key for decryption")
	}

	gethKey, err := keystore.DecryptKey(keyJSON, adulteratedPassword(password))
	if err != nil {
		return KeyV2{}, errors.Wrapf(err, "could not decrypt VRF key %s", export.PublicKey.String())
	}

	key := Raw(gethKey.PrivateKey.D.Bytes()).Key()
	return key, nil
}

// passwordPrefix is added to the beginning of the passwords for
// EncryptedVRFKey's, so that VRF keys can't casually be used as ethereum
// keys, and vice-versa. If you want to do that, DON'T.
var passwordPrefix = "don't mix VRF and Ethereum keys!"

func adulteratedPassword(password string) string {
	return passwordPrefix + password
}
