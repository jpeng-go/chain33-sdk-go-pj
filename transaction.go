package sdk

import (
	"encoding/hex"
	"errors"
	"github.com/golang/protobuf/proto"
	"gitlab.33.cn/pengjun/chain33-sdk-go/crypto"
)

func SignRawTransaction(raw string, privateKey string, signType string) (string, error) {
	var tx Transaction
	txByteData, err := FromHex(raw)
	if err != nil {
		return "", err
	}

	err = proto.Unmarshal(txByteData, &tx)
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

	key, err := FromHex(privateKey)
	if err != nil {
		return "", err
	}
	pub := signer.PubKeyFromPrivate(key)
	data, err := proto.Marshal(&tx)
	if err != nil {
		return "", err
	}
	signature := signer.Sign(data, key)
	tx.Signature = &Signature{
		Ty:        1,
		Pubkey:    pub,
		Signature: signature,
	}

	data, err = proto.Marshal(&tx)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(data), nil
}
