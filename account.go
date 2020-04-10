package sdk

import (
	"gitlab.33.cn/pengjun/chain33-sdk-go/crypto"
)

type Account struct {
	PrivateKey  []byte
	PublicKey   []byte
	Address     string
	SignType    string
}

func NewAccount(signType string) (*Account, error) {
    if signType == "" {
    	signType = crypto.SECP256k1
	}

	account := Account{}
	account.SignType = signType

	driver := crypto.NewSignDriver(signType)
	account.PrivateKey = driver.GeneratePrivateKey()
	account.PublicKey  = driver.PubKeyFromPrivate(account.PrivateKey)

	addr, err := crypto.PubKeyToAddress(account.PublicKey)
	if err != nil {
		return nil, err
	}
	account.Address = addr

	return &account, nil
}