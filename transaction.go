package sdk

import (
	"encoding/hex"
	"errors"
	"github.com/jpeng-go/chain33-sdk-go/crypto"
	"github.com/jpeng-go/chain33-sdk-go/crypto/gm"
	"github.com/jpeng-go/chain33-sdk-go/types"
)

func SignRawTransaction(raw string, privateKey string, signType string) (string, error) {
	var tx types.Transaction
	txByteData, err := types.FromHex(raw)
	if err != nil {
		return "", err
	}

	err = types.Decode(txByteData, &tx)
	if err != nil {
		return "", err
	}
	tx.Signature = nil

	if signType == "" {
		signType = crypto.SECP256k1
	}

	key, err := types.FromHex(privateKey)
	if err != nil {
		return "", err
	}

	if signType == crypto.SECP256k1 {
		pub := crypto.PubKeyFromPrivate(key)

		data := types.Encode(&tx)
		signature := crypto.Sign(data, key)
		tx.Signature = &types.Signature{
			Ty:        1,
			Pubkey:    pub,
			Signature: signature,
		}
	} else if signType == crypto.SM2 {
		pub := gm.PubKeyFromPrivate(key)

		data := types.Encode(&tx)
		signature := gm.SM2Sign(data, key, nil)
		tx.Signature = &types.Signature{
			Ty:        1,
			Pubkey:    pub,
			Signature: signature,
		}
	} else if signType == crypto.ED25519 {
		// TODO
	} else {
		return "", errors.New("sign type not support")
	}

	return hex.EncodeToString(types.Encode(&tx)), nil
}
