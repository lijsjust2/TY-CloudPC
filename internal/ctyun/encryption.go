// Package ctyun 保活校验响应加密（移植自原 C# 版 Encryption.cs：
// 自定义 OAEP 填充 + RSA 模幂运算，SHA1 + MGF1）
package ctyun

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"math/big"
)

// Encryptor 无状态加密器（对齐原版 AuthMechanism = 1）
type Encryptor struct {
	AuthMechanism uint32
}

func NewEncryptor() *Encryptor {
	return &Encryptor{AuthMechanism: 1}
}

// Execute 处理服务端下发的 "REDEQ" 保活校验报文，返回加密响应
func (e *Encryptor) Execute(key []byte) []byte {
	// 原版：跳过前 16 字节头部
	if len(key) < 16+166 {
		return nil
	}
	data := key[16:]
	// 公钥 N：data[32:161]（129 字节大端）
	n := new(big.Int).SetBytes(data[32 : 32+129])
	// 指数 E：data[163:166]（3 字节大端）
	eVal := int(data[163])<<16 | int(data[164])<<8 | int(data[165])
	encrypted := oaepEncrypt(128, n, eVal)
	// 封装：4 字节小端 AuthMechanism + 密文
	out := make([]byte, 4+len(encrypted))
	binary.LittleEndian.PutUint32(out, e.AuthMechanism)
	copy(out[4:], encrypted)
	return out
}

// oaepEncrypt 自定义 OAEP 填充后做 RSA 模幂：c = m^e mod n
func oaepEncrypt(keyLen int, n *big.Int, e int) []byte {
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return nil
	}
	const hLen = 20
	dbLen := keyLen - hLen - 1 // 107
	db := make([]byte, dbLen)
	// DB = Hash(L) || PS || 01 || M，L 为空串
	lHash := sha1.Sum(nil)
	copy(db, lHash[:])
	db[dbLen-2] = 1 // 对齐原版 db[db.Length - 1 - label.Length - 1]，label 为空
	// MGF1 掩码
	dbMask := mgf1(seed, dbLen)
	for i := range db {
		db[i] ^= dbMask[i]
	}
	seedMask := mgf1(db, hLen)
	for i := range seed {
		seed[i] ^= seedMask[i]
	}
	// EM = 00 || MaskedSeed || MaskedDB
	em := make([]byte, keyLen)
	copy(em[1:1+hLen], seed)
	copy(em[1+hLen:], db)
	// RSA：m^e mod n
	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, big.NewInt(int64(e)), n)
	result := c.Bytes()
	if len(result) == keyLen {
		return result
	}
	final := make([]byte, keyLen)
	copy(final[keyLen-len(result):], result)
	return final
}

// mgf1 MGF1 掩码生成函数（SHA1），对齐原版 P 函数
func mgf1(seed []byte, maskLen int) []byte {
	mask := make([]byte, maskLen)
	var counter uint32
	offset := 0
	for offset < maskLen {
		h := sha1.New()
		h.Write(seed)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		h.Write(ctr[:])
		hash := h.Sum(nil)
		copyLen := len(hash)
		if remain := maskLen - offset; copyLen > remain {
			copyLen = remain
		}
		copy(mask[offset:offset+copyLen], hash[:copyLen])
		offset += len(hash)
		counter++
	}
	return mask
}
