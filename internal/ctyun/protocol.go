// Package ctyun WebSocket 二进制消息协议（移植自原 C# 版 SendInfo.cs）
package ctyun

import (
	"encoding/binary"
)

// SendInfo 报文结构：Type(2 字节小端) + Length(4 字节小端) + Data(N 字节)
type SendInfo struct {
	Type uint16
	Data []byte
}

// ToBuffer 序列化报文；isBuildMsg 为 true 时额外携带 8 字节构建头
//（dataLen + 固定值 8），对齐原版 ToBuffer(true)
func (s *SendInfo) ToBuffer(isBuildMsg bool) []byte {
	msgLength := 0
	if isBuildMsg {
		msgLength = 8
	}
	dataLen := len(s.Data)
	buf := make([]byte, 2+4+msgLength+dataLen)
	binary.LittleEndian.PutUint16(buf[0:2], s.Type)
	binary.LittleEndian.PutUint32(buf[2:6], uint32(msgLength+dataLen))
	if isBuildMsg {
		binary.LittleEndian.PutUint32(buf[6:10], uint32(dataLen))
		binary.LittleEndian.PutUint32(buf[10:14], 8)
	}
	copy(buf[6+msgLength:], s.Data)
	return buf
}

// ParseSendInfos 从缓冲区还原报文列表，含半包/残缺数据与全零填充处理（对齐原版 FromBuffer）
func ParseSendInfos(buffer []byte) []SendInfo {
	var results []SendInfo
	if len(buffer) == 0 {
		return results
	}
	offset := 0
	for offset+6 <= len(buffer) {
		typ := binary.LittleEndian.Uint16(buffer[offset : offset+2])
		dataLen := int(int32(binary.LittleEndian.Uint32(buffer[offset+2 : offset+6])))
		// 长度非法或剩余字节不足：视为半包，剩余数据整体作为一条残缺报文
		if dataLen < 0 || offset+6+dataLen > len(buffer) {
			remaining := len(buffer) - offset
			if remaining > 0 {
				remainingData := make([]byte, remaining)
				copy(remainingData, buffer[offset:])
				results = append(results, SendInfo{Type: typ, Data: remainingData})
			}
			break
		}
		info := SendInfo{Type: typ}
		if dataLen > 0 {
			info.Data = make([]byte, dataLen)
			copy(info.Data, buffer[offset+6:offset+6+dataLen])
		}
		results = append(results, info)
		offset += 6 + dataLen
		// 末尾全零填充：直接结束，避免产生空包
		if offset+6 > len(buffer) && offset < len(buffer) {
			allZero := true
			for i := offset; i < len(buffer); i++ {
				if buffer[i] != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				break
			}
		}
	}
	return results
}
