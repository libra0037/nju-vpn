package ztna

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

// 固定字节来自线上帧契约；不调用被测编码器生成种子或期望值。
func FuzzReadFrame(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x05, 0x95, 0x00, 0x00},
		{0x05, 0x94, 0x00, 0x03, 1, 2, 3},
		{0x05, 0x93, 0x00, 0x00, 0x02, '{', '}'},
		{0x05, 0x96, 0x01, 0x00, 0x02, '[', ']'},
		{0x05, 0x94, 0xff, 0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := readFrame(bufio.NewReader(bytes.NewReader(input)))
		header := 0
		if len(input) >= 2 && input[0] == 0x05 {
			switch input[1] {
			case 0x94, 0x95:
				header = 4
			case 0x93, 0x96:
				header = 5
			}
		}
		if header == 0 || len(input) < header {
			if err == nil {
				t.Fatal("接受了未知或不完整的帧头")
			}
			return
		}
		size := int(binary.BigEndian.Uint16(input[header-2 : header]))
		if len(input)-header < size {
			if err == nil {
				t.Fatal("接受了不完整的帧载荷")
			}
			return
		}
		if err != nil || got.cmd != input[1] || !bytes.Equal(got.payload, input[header:header+size]) {
			t.Fatal("完整帧未按线上长度字段解析")
		}
		if header == 5 && got.status != input[2] {
			t.Fatal("状态字节解析错误")
		}
	})
}

func FuzzSplitPackets(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x45},
		{0x45, 0, 0xff, 0xff},
		{0x60, 0, 0, 0},
		{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		packets, rest, err := splitPackets(input)
		if err != nil {
			return
		}
		position := 0
		for _, packet := range packets {
			if len(packet) < 20 || packet[0]>>4 != 4 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
				t.Fatal("输出了长度或版本错误的 IP 包")
			}
			if len(input)-position < len(packet) || !bytes.Equal(input[position:position+len(packet)], packet) {
				t.Fatal("输出包改变了输入内容或次序")
			}
			position += len(packet)
		}
		if !bytes.Equal(input[position:], rest) {
			t.Fatal("未完成数据被丢弃或复制")
		}
	})
}
