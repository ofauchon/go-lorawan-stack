// Copyright © 2021. All rights reserved.
// Author: Olivier Fauchon.
// Contacts: <ofauchon2204@gmail.com>.
// License: https://opensource.org/licenses/MIT
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

/*
 * LmicReset
 * LmicStartJoining
 */
package lorawan

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"math"

	"github.com/jacobsa/crypto/cmac"
)

// todo: Tests and examples

const TIMEOUT = 1

type LoraWanStack struct {
	Session LoraSession
	Otaa    LoraOtaa
	radio   LoraRadio
}

type LoraEvent struct {
	eventType int
	eventData []byte
}

//LoraSession is used to store session data of a LoRaWAN session
type LoraSession struct {
	NwkSKey    [16]uint8
	AppSKey    [16]uint8
	DevAddr    [4]uint8
	FCntDown   uint32
	FCntUp     uint32
	CFList     [16]uint8
	RXDelay    uint8
	DLSettings uint8
}

//LoraOtaa is used to store session data of a LoRaWAN session
type LoraOtaa struct {
	DevEUI   [8]uint8
	AppEUI   [8]uint8
	AppKey   [16]uint8
	DevNonce [2]uint8
	AppNonce [3]uint8
	NetID    [3]uint8
}

const (
	EVENT_JOINING = iota
	EVENT_JOINED
)


// SetOOTA configure AppEUI, DevEUI, AppKey for the device
func (r *LoraWanStack) SetOtaa(appEUI [8]uint8, devEUI [8]uint8, appKey [16]uint8) {
	r.Otaa.AppEUI = appEUI
	r.Otaa.DevEUI = devEUI
	r.Otaa.AppKey = appKey
}

// GenerateJoinRequest Generates a Lora Join request
func (r *LoraWanStack) GenerateJoinRequest() ([]uint8, error) {
	// TODO: Add checks
	var buf []uint8
	buf = append(buf, 0x00)
	buf = append(buf, revertByteArray(r.Otaa.AppEUI[:])...)
	buf = append(buf, revertByteArray(r.Otaa.DevEUI[:])...)
	buf = append(buf, revertByteArray(r.Otaa.DevNonce[:])...)
	mic := r.genPayloadMIC(buf, r.Otaa.AppKey)
	buf = append(buf, mic[:]...)
	return buf, nil
}

// DecodeJoinAccept Decodes a Lora Join Accept packet
func (r *LoraWanStack) DecodeJoinAccept(phyPload []uint8) error {
	data := phyPload[1:] // Remove trailing 0x20
	// Prepare AES Cipher
	block, err := aes.NewCipher(r.Otaa.AppKey[:])
	if err != nil {
		return errors.New("Lora Cipher error 1")
	}
	buf := make([]byte, len(data))
	for k := 0; k < len(data)/aes.BlockSize; k++ {
		block.Encrypt(buf[k*aes.BlockSize:], data[k*aes.BlockSize:])
	}
	copy(r.Otaa.AppNonce[:], buf[0:3])
	copy(r.Otaa.NetID[:], buf[3:6])
	copy(r.Session.DevAddr[:], buf[6:10])
	r.Session.DLSettings = buf[10]
	r.Session.RXDelay = buf[11]

	if len(buf) > 16 {
		copy(r.Session.CFList[:], buf[12:28])
	}
	rxMic := buf[len(buf)-4:]

	dataMic := []byte{}
	dataMic = append(dataMic, phyPload[0])
	dataMic = append(dataMic, r.Otaa.AppNonce[:]...)
	dataMic = append(dataMic, r.Otaa.NetID[:]...)
	dataMic = append(dataMic, r.Session.DevAddr[:]...)
	dataMic = append(dataMic, r.Session.DLSettings)
	dataMic = append(dataMic, r.Session.RXDelay)
	dataMic = append(dataMic, r.Session.CFList[:]...)
	computedMic := r.genPayloadMIC(dataMic[:], r.Otaa.AppKey)
	if !bytes.Equal(computedMic[:], rxMic[:]) {
		return errors.New("Wrong Mic")
	}

	// Generate NwkSKey
	// NwkSKey = aes128_encrypt(AppKey, 0x01|AppNonce|NetID|DevNonce|pad16)
	sKey := []byte{}
	sKey = append(sKey, 0x01)
	sKey = append(sKey, r.Otaa.AppNonce[:]...)
	sKey = append(sKey, r.Otaa.NetID[:]...)
	sKey = append(sKey, r.Otaa.DevNonce[:]...)
	for i := 0; i < 7; i++ {
		sKey = append(sKey, 0x00) // PAD to 16
	}
	block.Encrypt(buf, sKey)
	copy(r.Session.NwkSKey[:], buf[0:16])

	// Generate AppSKey
	// AppSKey = aes128_encrypt(AppKey, 0x02|AppNonce|NetID|DevNonce|pad16)
	sKey[0] = 0x02
	block.Encrypt(buf, sKey)
	copy(r.Session.AppSKey[:], buf[0:16])

	// Reset counters
	r.Session.FCntDown = 0
	r.Session.FCntUp = 0

	return nil
}

// GenMessage Forge an uplink message
func (r *LoraWanStack) GenMessage(dir uint8, payload []uint8) ([]uint8, error) {
	var buf []uint8
	buf = append(buf, 0b01000000) // FHDR Unconfirmed up
	buf = append(buf, r.Session.DevAddr[:]...)
	buf = append(buf, 0x00)                                                            // FCtl : No ADR, No RFU, No ACK, No FPending, No FOpt
	buf = append(buf, uint8((r.Session.FCntUp>>8)&0xFF), uint8(r.Session.FCntUp&0xFF)) // FCnt Up
	buf = append(buf, 0x01)                                                            // FPort=1

	fCnt := uint32(0)
	if dir == 0 {
		fCnt = r.Session.FCntUp
	} else {
		fCnt = r.Session.FCntDown
	}
	data, err := r.genFRMPayload(dir, r.Session.DevAddr[:], fCnt, payload, false)
	if err != nil {
		return nil, err
	}
	buf = append(buf, data[:]...)

	mic := r.calcMessageMIC(buf, r.Session.NwkSKey, dir, r.Session.DevAddr[:], fCnt, uint8(len(buf)))
	buf = append(buf, mic[:]...)

	return buf, nil
}

// encryptMessage encrypts Frame Header (Sec 4.3.3 lorawan 1.0.3 specification)
// dir : 0(uplink) 1(downlink)
// addr : devAddr
// fCnt : Frame counter (up or down)
func (r *LoraWanStack) genFRMPayload(dir uint8, addr []uint8, fCnt uint32, payload []byte, isFOpts bool) ([]byte, error) {
	k := len(payload) / aes.BlockSize
	if len(payload)%aes.BlockSize != 0 {
		k++
	}
	if k > math.MaxUint8 {
		return nil, errors.New("Payload too big !")
	}
	encrypted := make([]byte, 0, k*16)
	cipher, err := aes.NewCipher(r.Session.AppSKey[:])
	if err != nil {
		panic(err)
	}

	var a [aes.BlockSize]byte
	a[0] = 0x01
	a[5] = dir
	copy(a[6:10], addr)
	binary.LittleEndian.PutUint32(a[10:14], fCnt)
	var s [aes.BlockSize]byte
	var b [aes.BlockSize]byte
	for i := uint8(0); i < uint8(k); i++ {
		copy(b[:], payload[i*aes.BlockSize:])
		if !isFOpts {
			a[15] = i + 1
		}
		cipher.Encrypt(s[:], a[:])
		for j := 0; j < aes.BlockSize; j++ {
			b[j] = b[j] ^ s[j]
		}
		encrypted = append(encrypted, b[:]...)
	}
	return encrypted[:len(payload)], nil
}

// getPayloadMIC computes MIC given the payload and the key
func (r *LoraWanStack) genPayloadMIC(payload []uint8, key [16]uint8) [4]uint8 {
	var mic [4]uint8
	hash, _ := cmac.New(key[:])
	hash.Write(payload)
	hb := hash.Sum([]byte{})
	copy(mic[:], hb[0:4])
	return mic
}

// getPayloadMIC computes MIC given the payload and the key
func (r *LoraWanStack) calcMessageMIC(payload []uint8, key [16]uint8, dir uint8, addr []byte, fCnt uint32, lenMessage uint8) [4]uint8 {
	var b0 []byte
	b0 = append(b0, 0x49, 0x00, 0x00, 0x00, 0x00)
	b0 = append(b0, dir)
	b0 = append(b0, addr[:]...)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], fCnt)
	b0 = append(b0, b[:]...)
	b0 = append(b0, 0x00)
	b0 = append(b0, lenMessage)

	var full []byte
	full = append(full, b0...)
	full = append(full, payload...)

	var mic [4]uint8
	hash, _ := cmac.New(key[:])
	hash.Write(full)
	hb := hash.Sum([]byte{})
	copy(mic[:], hb[0:4])
	return mic
}

// AttachLoraRadio registers the Lora Radio Driver
func (r *LoraWanStack) AttachLoraRadio(pRadio LoraRadio) {
	r.radio = pRadio
}

//LoraWanJoin() initiate a Lorawan JOIN sequence
func (r *LoraWanStack) LoraWanJoin() error {
	var resp []uint8

	if r.radio == nil{
		return errors.New("No lora Radio attached")
	}

	// Send join packet
	println("lorawan: Start JOIN sequence")
	payload, err := r.GenerateJoinRequest()
	if err != nil {
		return err
	}
	println("lorawan: Send JOIN request ", bytesToHexString(payload))
	r.radio.SetLoraCrc(true)
	r.radio.SetLoraIqMode(0) // IQ Standard
	r.radio.LoraTx(payload, TIMEOUT)
	if err != nil {
		return err
	}

	// Wait for JoinAccept
	println("lorawan: Wait for JOINACCEPT for 10s")
	r.radio.SetLoraIqMode(1) // IQ Inverted
	for i := 0; i < 10; i++ {
		resp, err = r.radio.LoraRx(TIMEOUT)
		if err != nil {
			return err
		}
		if resp != nil {
			break
		}
	}
	if resp == nil {
		errors.New("No JoinAccept packet received")
	}
	println("lorawan: Received packet:", bytesToHexString(resp))

	err = r.DecodeJoinAccept(resp)
	if err != nil {
		return err
	}
	println("lorawan: Valid JOINACCEPT, now connected")
	println("lorawan: |  DevAddr: ", bytesToHexString(r.Session.DevAddr[:]), " (LSB)")
	println("lorawan: |  NetID  : ", bytesToHexString(r.Otaa.NetID[:]))
	println("lorawan: |  NwkSKey: ", bytesToHexString(r.Session.NwkSKey[:]))
	println("lorawan: |  AppSKey: ", bytesToHexString(r.Session.AppSKey[:]))

	return nil
}

//LoraWanJoin() initiate a Lorawan JOIN sequence
func (r *LoraWanStack) LoraSendUplink(data []uint8) error {
	println("lorawan: Send UPLINK  ", bytesToHexString(data))
	payload, err := r.GenMessage(0, []byte(data))
	if err != nil {
		return err
	}
	r.radio.SetLoraCrc(true)
	r.radio.SetLoraIqMode(0) // IQ Standard
	r.radio.LoraTx(payload, TIMEOUT)
	if err != nil {
		return err
	}
	return nil
}