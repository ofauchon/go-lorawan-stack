package lorawan

type LoraRadio interface {
	LoraTx(pkt []uint8, timeoutMs uint32) error
	LoraRx(timeoutMs uint32) ([]uint8, error)
	SetLoraFrequency(freq uint32)
	SetLoraIqMode(mode uint8)
	SetLoraCodingRate(cr uint8)
	SetLoraBandwidth(bw uint8)
	SetLoraCrc(enable bool)
	SetLoraSpreadingFactor(sf uint8)
}

type LoraRadioRFSwitch interface {
	InitRFSwitch()
	SetRfSwitchMode(mode int) error
}
