package bip32

import (
	ecc "github.com/sea-project/crypto-ecc-s256"
	ecdsa "github.com/sea-project/crypto-signature-ecdsa"
	"testing"
)

type test struct {
	Key []byte
}

func Test_Main(t *testing.T) {
	mkey, err := NewMasterKey([]byte("qiqi"))
	if err != nil {
		t.Log(err)
	}
	t.Log(JsonString(mkey))
	t.Log(mkey.String())
	t.Log(mkey.PublicKey())
	t.Log(PubKeyToAddr(mkey.PublicKey().Key))

}

func Test_NewKeyFromMasterKey(t *testing.T) {
	mk := "xprv9s21ZrQH143K3JE9v2j6F2zq2amvgbYDuYVo4dzvFwmRCdjT9ddjD3hszU58SosoAMj2JGm6oC3oFppS5HhtrVbg15uWrymsuwNPVyJbfu1"
	// 先base58反序列化
	// 在key反序列化
	masterkey, err := B58Deserialize(mk)
	if err != nil {
		t.Log(err)
	}
	t.Log("主私钥：", masterkey)
	child, err := masterkey.NewChildKey(ParseHDNum(0))
	if err != nil {
		t.Log(err)
	}
	child, err = child.NewChildKey(ParseHDNum(0))
	if err != nil {
		t.Log(err)
	}
	child, err = child.NewChildKey(ParseHDNum(36))
	if err != nil {
		t.Log(err)
	}
	pri, _ := ecdsa.PrivKeyFromBytes(ecc.S256(), child.Key)
	t.Log("子私钥：", ecdsa.PrvKeyToWIF(pri, true))

	t.Log(PubKeyToAddr(child.PublicKey().Key))
}

func Test_CheckKeyPath(t *testing.T) {
	index_arr, err := CheckKeyPath("m/44'/60'/0'/0/1")
	t.Log(err)
	t.Log(index_arr)
}

func Test_DeriveFromKeyPath(t *testing.T) {
	mk := "xprv9s21ZrQH143K3JE9v2j6F2zq2amvgbYDuYVo4dzvFwmRCdjT9ddjD3hszU58SosoAMj2JGm6oC3oFppS5HhtrVbg15uWrymsuwNPVyJbfu1"
	// 先base58反序列化
	// 在key反序列化
	masterkey, err := B58Deserialize(mk)
	if err != nil {
		t.Log(err)
	}
	t.Log("主私钥：", masterkey)
	child, err := masterkey.DeriveFromKeyPath("m/0'/0'/36'")
	if err != nil {
		t.Log(err)
	}
	pri, _ := ecdsa.PrivKeyFromBytes(ecc.S256(), child.Key)
	t.Log("子私钥：", ecdsa.PrvKeyToWIF(pri, true))

	t.Log(PubKeyToAddr(child.PublicKey().Key))
}
