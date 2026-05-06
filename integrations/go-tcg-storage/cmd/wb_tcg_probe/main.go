package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/open-source-firmware/go-tcg-storage/pkg/core"
	"github.com/open-source-firmware/go-tcg-storage/pkg/drive"
)

type ProbeInput struct {
	ResponseHex string `json:"response_hex"`
	Proto       int    `json:"proto"`
	SPS         int    `json:"sps"`
	ComID       int    `json:"com_id"`
}

type ProbeOutput struct {
	OK          bool    `json:"ok"`
	Error       *string `json:"error"`
	ResponseLen int     `json:"response_len"`
	ParsedHex   string  `json:"parsed_hex"`
	IFRecvCalls int     `json:"if_recv_calls"`
	LatencyUS   float64 `json:"latency_us"`
}

// fakeDrive implements drive.DriveIntf backed by a fixed byte slice.
// IFRecv copies the preloaded bytes into the caller's buffer, simulating a
// TPer response at the plainCom.Receive boundary.
type fakeDrive struct {
	data      []byte
	recvCalls int
}

func (f *fakeDrive) IFRecv(_ drive.SecurityProtocol, _ uint16, buf *[]byte) error {
	f.recvCalls++
	dst := *buf
	n := copy(dst, f.data)
	for i := n; i < len(dst); i++ {
		dst[i] = 0
	}
	return nil
}

func (f *fakeDrive) IFSend(_ drive.SecurityProtocol, _ uint16, _ []byte) error {
	return nil
}

func (f *fakeDrive) Identify() (*drive.Identity, error) {
	return &drive.Identity{Protocol: "fake", Model: "wb-fake", SerialNumber: "000000", Firmware: "0.0"}, nil
}

func (f *fakeDrive) SerialNumber() ([]byte, error) {
	return []byte("000000"), nil
}

func (f *fakeDrive) Close() error { return nil }

func main() {
	start := time.Now()

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		exitWithError(start, fmt.Sprintf("failed to read stdin: %v", err))
		return
	}

	var input ProbeInput
	if err := json.Unmarshal(raw, &input); err != nil {
		exitWithError(start, fmt.Sprintf("invalid input json: %v", err))
		return
	}

	responseBytes, err := hex.DecodeString(input.ResponseHex)
	if err != nil {
		exitWithError(start, fmt.Sprintf("invalid response_hex: %v", err))
		return
	}

	fd := &fakeDrive{data: responseBytes}
	hp := core.InitialHostProperties
	tp := core.InitialTPerProperties
	var com core.CommunicationIntf = core.NewPlainCommunication(fd, hp, tp)

	ses := &core.Session{
		ComID: core.ComID(input.ComID),
	}

	data, receiveErr := com.Receive(ses)
	latency := float64(time.Since(start).Microseconds())

	if receiveErr != nil {
		msg := receiveErr.Error()
		out := ProbeOutput{
			OK:          false,
			Error:       &msg,
			ResponseLen: len(responseBytes),
			ParsedHex:   "",
			IFRecvCalls: fd.recvCalls,
			LatencyUS:   latency,
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		os.Exit(1)
		return
	}

	_ = json.NewEncoder(os.Stdout).Encode(ProbeOutput{
		OK:          true,
		Error:       nil,
		ResponseLen: len(responseBytes),
		ParsedHex:   hex.EncodeToString(data),
		IFRecvCalls: fd.recvCalls,
		LatencyUS:   latency,
	})
}

func exitWithError(start time.Time, msg string) {
	out := ProbeOutput{
		OK:          false,
		Error:       &msg,
		ResponseLen: 0,
		ParsedHex:   "",
		IFRecvCalls: 0,
		LatencyUS:   float64(time.Since(start).Microseconds()),
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	os.Exit(1)
}
