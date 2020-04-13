package  crypto

import (
	"fmt"
	"github.com/jpeng-go/chain33-sdk-go/types"
	"math/big"
	"testing"
)

func TestAES(t *testing.T) {
	var text = "hello aes"
	var key = GetRandBytes(32)

	cipherText, err := AESCBCPKCS7Encrypt(key, []byte(text))
	if err != nil {
		fmt.Println(err)
		return
	}

	cipher, err := AESCBCPKCS7Decrypt(key, cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(cipher))
}

func TestUtil(t *testing.T) {
	var num = big.NewInt(123)

	fmt.Println(num)
	numstr := types.BigToString(num)
	fmt.Println(numstr)
	res := types.StringToBig(numstr)
	fmt.Println(res)
}