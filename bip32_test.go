package bip32

import (
	addr "github.com/sea-project/crypto-address-p2pkh"
	ecc "github.com/sea-project/crypto-ecc-s256"
	ecdsa "github.com/sea-project/crypto-signature-ecdsa"
	bytes "github.com/sea-project/stdlib-bytes"
	"testing"
)

type test struct {
	Key []byte
}

func Test_Main(t *testing.T) {
	hexPrv := "962a3216577de604a0a44086e78960263131b05b92f5ccd3b1d494acf05d3057"
	prvB, _ := bytes.Hex2Bytes(hexPrv)
	mkey, err := NewMasterKey(prvB)
	if err != nil {
		t.Log(err)
	}
	t.Log(JsonString(mkey))
	t.Log(mkey.String())
	t.Log(mkey.PublicKey())
	t.Log(PubKeyToAddr(mkey.PublicKey().Key))

	ck, err := mkey.DeriveFromKeyPath("m/44'/0'/0'/0/1")
	if err != nil {
		t.Fatal(err)
	}
	eckey, _ := ecdsa.ToECDSA(ck.Key, true)
	btcAddr := addr.ToBTCAddress(eckey.ToPubKey())
	t.Log(btcAddr)
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
	index_arr, err := CheckKeyPath("m/44'/60'/0'/2147483648/2")
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
