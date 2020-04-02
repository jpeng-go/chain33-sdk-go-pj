package sdk

import (
	"gitlab.33.cn/pengjun/chain33-sdk-go/crypto"
)

type Account struct {
	privateKey  string
	publicKey   string
	address     string
	signType    string
}

func NewAccount(signType string) (*Account, error) {
    if signType == "" {
    	signType = crypto.SECP256k1
	}

	account := Account{}
	account.signType = signType

	driver := crypto.NewSignDriver(signType)
	privKey := driver.GeneratePrivateKey()
	account.privateKey = ToHex(privKey)

	pubKey := driver.PubKeyFromPrivate(privKey)
	account.publicKey = ToHex(pubKey)

	addr, err := crypto.AddressFromPubKey(pubKey)
	if err != nil {
		return nil, err
	}
	account.address = addr

	return &account, nil
}