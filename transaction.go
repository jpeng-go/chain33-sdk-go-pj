package sdk

import (
	"encoding/hex"
	"errors"
	"github.com/jpeng-go/chain33-sdk-go/crypto"
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
	signer := crypto.NewSignDriver(signType)
	if signer == nil {
		return "", errors.New("signType error")
	}

	key, err := types.FromHex(privateKey)
	if err != nil {
		return "", err
	}
	pub := signer.PubKeyFromPrivate(key)

	data := types.Encode(&tx)
	signature := signer.Sign(data, key)
	tx.Signature = &types.Signature{
		Ty:        1,
		Pubkey:    pub,
		Signature: signature,
	}

	data = types.Encode(&tx)
	return hex.EncodeToString(data), nil
}
