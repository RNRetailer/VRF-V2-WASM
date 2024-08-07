package btcec

import (
	secp "github.com/RNRetailer/rng/dcrd/secp256k1"
)

// PrivateKey wraps an ecdsa.PrivateKey as a convenience mainly for signing
// things with the private key without having to directly import the ecdsa
// package.
type PrivateKey = secp.PrivateKey
