package lorawan

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

/*
*   https://runkit.com/avbentem/deciphering-a-lorawan-otaa-join-accept
*
*     Message Type = Join Request
* 			Appkey = B6B53F4A168A7A88BDF7EA135CE9CFCA
*           AppEUI = 70B3D57ED00000DC
*           DevEUI = 00AFEE7CF5ED6F1E
*         DevNonce = CC85
*              MIC = 587FE913
* =>  00 DC 00 00 D0 7E D5 B3 70 1E 6F ED F5 7C EE AF 00 85 CC 58 7F E9 13
 */
func TestJoinRequest(t *testing.T) {

	l := &LoraWanStack{}
	l.Otaa.AppEUI = [8]byte{0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x00, 0x00, 0xDC}
	l.Otaa.DevEUI = [8]byte{0x00, 0xAF, 0xEE, 0x7C, 0xF5, 0xED, 0x6F, 0x1E}
	l.Otaa.AppKey = [16]byte{0xB6, 0xB5, 0x3F, 0x4A, 0x16, 0x8A, 0x7A, 0x88, 0xBD, 0xF7, 0xEA, 0x13, 0x5C, 0xE9, 0xCF, 0xCA}
	l.Otaa.DevNonce = [2]byte{0xCC, 0x85}

	fmt.Printf("*** TEST#1: Join Request\n")
	fmt.Printf("We'll try to encode a Lora Join Request packet  \n")
	expected := "00DC0000D07ED5B3701E6FEDF57CEEAF0085CC587FE913"
	tex, _ := hex.DecodeString(expected)

	j, _ := l.GenerateJoinRequest()

	fmt.Printf("AppEui:       %s\n", hex.EncodeToString(l.Otaa.AppEUI[:]))
	fmt.Printf("DevEui:       %s\n", hex.EncodeToString(l.Otaa.DevEUI[:]))
	fmt.Printf("AppKey:       %s\n", hex.EncodeToString(l.Otaa.AppKey[:]))
	fmt.Printf("DevNonce:     %s\n", hex.EncodeToString(l.Otaa.DevNonce[:]))
	fmt.Printf("Build    Join Request: %s\n", hex.EncodeToString(j[:]))
	fmt.Printf("Expected Join Request: %s\n", hex.EncodeToString(tex[:]))

	if bytes.Equal(j[:], tex[:]) {
		fmt.Println("ALL TESTS OK")
	} else {
		fmt.Println("=> ERROR ENCODING Join Request : Bad generated payload !! ")
	}

}

func TestJoinAccept(t *testing.T) {

	l := &LoraWanStack{}
	l.Otaa.AppEUI = [8]byte{0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x00, 0x00, 0xDC}
	l.Otaa.DevEUI = [8]byte{0x00, 0xAF, 0xEE, 0x7C, 0xF5, 0xED, 0x6F, 0x1E}
	l.Otaa.AppKey = [16]byte{0xB6, 0xB5, 0x3F, 0x4A, 0x16, 0x8A, 0x7A, 0x88, 0xBD, 0xF7, 0xEA, 0x13, 0x5C, 0xE9, 0xCF, 0xCA}
	l.Otaa.DevNonce = [2]byte{0xCC, 0x85}

	packet := "204DD85AE608B87FC4889970B7D2042C9E72959B0057AED6094B16003DF12DE145"
	t1, _ := hex.DecodeString(packet)

	fmt.Println("*** TEST#2 : Join Accept ")
	fmt.Printf(" We'll try to decode encrypted Lora Join Accept packet  (%s)\n", hex.EncodeToString(t1[:]))

	err := l.DecodeJoinAccept(t1)
	if err == nil {

		//	fmt.Printf("JoinAccept Decrypted:   %s\n", hex.EncodeToString(decoded))

		fmt.Printf("JoinAccept AppNonce: %s\n", hex.EncodeToString(l.Otaa.AppNonce[:]))
		fmt.Printf("JoinAccept NetID: %s\n", hex.EncodeToString(l.Otaa.NetID[:]))
		fmt.Printf("JoinAccept DevAddr: %s\n", hex.EncodeToString(l.Session.DevAddr[:]))
		fmt.Printf("JoinAccept DLSettings: %02X\n", l.Session.DLSettings)
		fmt.Printf("JoinAccept RXDelay: %02X\n", l.Session.RXDelay)
		fmt.Printf("JoinAccept CFList: %s\n", hex.EncodeToString(l.Session.CFList[:]))

		fmt.Printf("JoinAccept AppSkey: %s\n", hex.EncodeToString(l.Session.AppSKey[:]))
		fmt.Printf("JoinAccept NwkSKey: %s\n", hex.EncodeToString(l.Session.NwkSKey[:]))

		// What we expext to get
		t1, _ := hex.DecodeString("2C96F7028184BB0BE8AA49275290D4FC") //NwkSKey
		t2, _ := hex.DecodeString("F3A5C8F0232A38C144029C165865802C") //AppSKey

		if bytes.Equal(l.Session.NwkSKey[:], t1) && bytes.Equal(l.Session.AppSKey[:], t2) {
			fmt.Println("ALL TESTS OK")
		} else {
			fmt.Println("=> ERROR DECODING Join Accept : BAD NwkSKey or AppSKey !! ")
		}

	} else {
		fmt.Println("Error decoding Join Accept Packet", err)
	}

}

func TestUplinkMessage(t *testing.T) {

	l := &LoraWanStack{}
	l.Otaa.AppEUI = [8]byte{0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x00, 0x00, 0xDC}
	l.Otaa.DevEUI = [8]byte{0x00, 0xAF, 0xEE, 0x7C, 0xF5, 0xED, 0x6F, 0x1E}
	l.Otaa.AppKey = [16]byte{0xB6, 0xB5, 0x3F, 0x4A, 0x16, 0x8A, 0x7A, 0x88, 0xBD, 0xF7, 0xEA, 0x13, 0x5C, 0xE9, 0xCF, 0xCA}
	l.Otaa.DevNonce = [2]byte{0x85, 0xCC}

	fmt.Printf("*** TEST#1: Join Request\n")
	msg := []byte("aaabbb")
	fmt.Printf("We'll try to following payload '%s'[%s]\n", msg, hex.EncodeToString(msg[:]))

	payload, err := l.GenMessage(0, msg)
	if err == nil {
		fmt.Printf("UplinkMessage: %s\n", hex.EncodeToString(payload[:]))
	} else {
		println("testUplinkMEssage error", err)
	}

}

/*
func main() {

	l := &LoraWanStack{}
	l.Otaa.AppEUI = []byte{0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x00, 0x00, 0xDC}
	l.Otaa.DevEUI = []byte{0x00, 0xAF, 0xEE, 0x7C, 0xF5, 0xED, 0x6F, 0x1E}
	l.Otaa.AppKey = []byte{0xB6, 0xB5, 0x3F, 0x4A, 0x16, 0x8A, 0x7A, 0x88, 0xBD, 0xF7, 0xEA, 0x13, 0x5C, 0xE9, 0xCF, 0xCA}
	l.Otaa.DevNonce = []byte{0xCC, 0x85}

	fmt.Printf("TEST APPEUI: %s\n", hex.EncodeToString(l.Otaa.AppEUI[:]))
	fmt.Printf("TEST DEVEUI: %s\n", hex.EncodeToString(l.Otaa.DevEUI[:]))
	fmt.Printf("TEST APPKEY: %s\n", hex.EncodeToString(l.Otaa.AppKey[:]))
	fmt.Printf("TEST DEVNONCE: %s\n", hex.EncodeToString(l.Otaa.DevNonce[:]))

	testJoinRequest(l)
	testJoinAccept(l)
	testUplinkMessage(l)

}
*/
