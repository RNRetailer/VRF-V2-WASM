package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"syscall/js"
	"time"

	"github.com/RNRetailer/rng/chainlink_develop/secp256k1"
	"github.com/RNRetailer/rng/chainlink_develop/vrf/proof"
	"github.com/RNRetailer/rng/chainlink_develop/vrfkey"
	"github.com/RNRetailer/rng/go_eth/accounts/abi"
	"github.com/RNRetailer/rng/go_eth/common"
	"github.com/RNRetailer/rng/go_eth/common/hexutil"
	"github.com/RNRetailer/rng/go_eth/crypto"
	"github.com/RNRetailer/rng/kyber"
)

func point() kyber.Point {
	return vrfkey.Secp256k1Curve.Point()
}

// SolidityProof contains precalculations which VRF.sol needs to verify proofs
type SolidityProof struct {
	P                           *vrfkey.Proof  // The core proof
	UWitness                    common.Address // Address of P.C*P.PK+P.S*G
	CGammaWitness, SHashWitness kyber.Point    // P.C*P.Gamma, P.S*HashToCurve(P.Seed)
	ZInv                        *big.Int       // Inverse of Z coord from ProjectiveECAdd(CGammaWitness, SHashWitness)
}

func SolidityPrecalculations(p *vrfkey.Proof) (*SolidityProof, error) {
	var rv SolidityProof
	rv.P = p
	c := secp256k1.IntToScalar(p.C)
	s := secp256k1.IntToScalar(p.S)
	u := point().Add(point().Mul(c, p.PublicKey), point().Mul(s, vrfkey.Generator))
	var err error
	rv.UWitness = secp256k1.EthereumAddress(u)
	rv.CGammaWitness = point().Mul(c, p.Gamma)
	hash, err := vrfkey.HashToCurve(p.PublicKey, p.Seed, func(*big.Int) {})
	if err != nil {
		return nil, err
	}
	rv.SHashWitness = point().Mul(s, hash)
	_, _, z := vrfkey.ProjectiveECAdd(rv.CGammaWitness, rv.SHashWitness)
	rv.ZInv = z.ModInverse(z, vrfkey.FieldSize)
	return &rv, nil
}

func GenericEncode(types []string, values ...interface{}) ([]byte, error) {
	if len(values) != len(types) {
		return nil, errors.New("must include same number of values as types")
	}
	var args abi.Arguments
	for _, t := range types {
		ty, _ := abi.NewType(t, "", nil)
		args = append(args, abi.Argument{Type: ty})
	}
	out, err := args.PackValues(values)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func generate(this js.Value, args []js.Value) interface{} {
	/// Orfer of arguments:
	// 0 numCount
	// 1 password
	// 2 senderAddr
	// 3 subID
	// 4 blockHash
	// 5 blockNum
	// 6 cbGasLimit
	// 7 numWords
	// 8 numWorkers

	// how many numbers to generate. default: 100
	numCount := args[0].Int()
	// password to decrypt the key with
	password := args[1].String()

	/// preseed information

	// sender of the requestRandomWords tx. default: ""
	senderAddr := args[2].String()

	// sub id
	subID := uint64(args[3].Int())

	/// seed information - can be fetched from a real chain's explorer

	// blockhash the request is in. default" ""
	blockhashStr := args[4].String()

	// block number the request is in. default: 10
	blockNumStr := args[5].String()
	blockNum, err := strconv.ParseUint(blockNumStr, 10, 64)
	PanicErr(err)

	// callback gas limit. default: 100_000
	cbGasLimit := args[6].Int()

	// num words. default: 1
	numWords := args[7].Int()

	// num workers. deault: runtime.NumCPU()
	numWorkers := uint64(args[8].Int())

	fileBytes := []byte("{\"PublicKey\":\"0x8f5bbd639829c8b5ad8724d96cf93a15cf6d8ed5f2cf7304899776ef8252d22800\",\"vrf_key\":{\"address\":\"d87b7ec9a37ee5a4a7252b3ef924b204b24f3ec5\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"8db11174e5d37f535be561c0fd9363a68b383916543d9cf8ce1c04102c65a398\",\"cipherparams\":{\"iv\":\"4b176326b2f24d14b2cb870e813f28a0\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"aa07a44029657fdd14cebfd0644a8e7505fbf7b6f9010ab6d45ff4b954a90da6\"},\"mac\":\"5382bd72094469d28a6d47862b1df0e7dce4293e6c1c9235163acca37ae5df61\"},\"version\":3}}")

	key, err := vrfkey.FromEncryptedJSON(fileBytes, password)
	PanicErr(err)

	keyHash := key.PublicKey.MustHash()
	sender := common.HexToAddress(senderAddr)
	blockhash := common.HexToHash(blockhashStr)

	// columns:
	// (keyHashHex, senderAddrHex, subID, nonce) preseed info
	// (preSeed, blockhash, blocknum, subID, cbGasLimit, numWords, senderAddrHex)
	// pubKeyHex, keyHashHex, senderAddrHex, subID, nonce, preSeed, blockhash, blocknum, cbGasLimit, numWords, finalSeed, proof..., randomNumber
	header := []string{
		"keyHashHex", "senderAddrHex", "subID", "nonce", "preSeed", "blockhash",
		"blocknum", "cbGasLimit", "numWords", "finalSeed",
		"proofPubKey", "proofGamma", "proofC", "proofS", "proofSeed",
		"randomNumber", "uWitness", "cGammaWitness", "sHashWitness", "zInv",
	}

	genProofs := func(
		nonceRange []uint64,
		outChan chan []string) {
		numIters := 0
		for nonce := nonceRange[0]; nonce <= nonceRange[1]; nonce++ {
			var record []string

			// construct preseed using typical preseed data
			preSeed := preseed(keyHash, sender, subID, nonce)
			record = append(record,
				keyHash.String(), sender.String(), // keyHash, sender addr
				fmt.Sprintf("%d", subID), fmt.Sprintf("%d", nonce), hexutil.Encode(preSeed[:]), // subId, nonce, preseed
				blockhashStr, fmt.Sprintf("%d", blockNum), // blockhash, blocknum
				fmt.Sprintf("%d", cbGasLimit), fmt.Sprintf("%d", numWords)) // cb gas limit, num words

			preseedData := proof.PreSeedDataV2{
				PreSeed:          preSeed,
				BlockHash:        blockhash,
				BlockNum:         blockNum,
				SubId:            subID,
				CallbackGasLimit: uint32(cbGasLimit),
				NumWords:         uint32(numWords),
				Sender:           sender,
			}
			finalSeed := proof.FinalSeedV2(preseedData)

			record = append(record, finalSeed.String())

			// generate proof
			pf, err2 := key.GenerateProof(finalSeed)
			PanicErr(err2)

			record = append(record,
				fmt.Sprintf("%s", pf.PublicKey), // pub key
				fmt.Sprintf("%s", pf.Gamma),     // gamma
				pf.C.String(), pf.S.String(),    // c, s
				pf.Seed.String(), pf.Output.String()) // seed, output

			solidityProof, err3 := SolidityPrecalculations(&pf)
			PanicErr(err3)

			record = append(record,
				solidityProof.UWitness.String(),
				fmt.Sprintf("%s", solidityProof.CGammaWitness),
				fmt.Sprintf("%s", solidityProof.SHashWitness),
				solidityProof.ZInv.String(),
			)

			if len(record) != len(header) {
				panic("record length doesn't match header length - update one of them?")
			}
			outChan <- record
			numIters++
		}
		fmt.Println("genProofs worker wrote", numIters, "records to channel")
	}

	rows := make([][]string, 1)

	gather := func(outChan chan []string) {
		for {
			select {
			case row := <-outChan:
				rows[0] = row
			case <-time.After(500 * time.Millisecond):
				// if no work is produced in this much time, we're probably done
				return
			}
		}
	}

	ranges := nonceRanges(1, uint64(numCount), numWorkers)

	fmt.Println("nonce ranges:", ranges, "generating proofs...")

	outC := make(chan []string)

	for _, nonceRange := range ranges {
		go genProofs(
			nonceRange,
			outC)
	}

	gather(outC)

	numbersJson, _ := json.Marshal(rows)

	// fmt.Println(string(numbersJson[:]))
	return string(numbersJson[:])
}

func main() {
	js.Global().Set("generate", js.FuncOf(generate))

	// keep the program alive so that `generate()` can continually be called from javascript
	select {}
}

func preseed(keyHash common.Hash, sender common.Address, subID, nonce uint64) [32]byte {
	encoded, err := GenericEncode(
		[]string{"bytes32", "address", "uint64", "uint64"},
		keyHash,
		sender,
		subID,
		nonce)
	PanicErr(err)

	preSeed := crypto.Keccak256(encoded)
	var preSeedSized [32]byte
	copy(preSeedSized[:], preSeed)
	return preSeedSized
}

func nonceRanges(start, end, numWorkers uint64) (ranges [][]uint64) {
	rangeSize := (end - start) / numWorkers
	for i := start; i <= end; i += rangeSize + 1 {
		j := i + rangeSize
		if j > end {
			j = end
		}

		ranges = append(ranges, []uint64{i, j})
	}
	return
}

func PanicErr(err error) {
	if err != nil {
		panic(err)
	}
}
