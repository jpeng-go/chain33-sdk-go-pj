package sdk

import (
	"encoding/hex"
	"github.com/golang/protobuf/proto"
	"gitlab.33.cn/pengjun/chain33-sdk-go/crypto"
)

func SignRawTransaction(raw string, privateKey []byte) (string, error) {
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

	signer := crypto.NewSignDriver("secp256k1")
	pub := signer.PubKeyFromPrivate(privateKey)
	data, err := proto.Marshal(&tx)
	if err != nil {
		return "", err
	}
	signature := signer.Sign(data, privateKey )
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
