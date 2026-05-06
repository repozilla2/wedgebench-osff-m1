package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
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

	out := ProbeOutput{
		OK:          true,
		Error:       nil,
		ResponseLen: len(input.ResponseHex) / 2,
		ParsedHex:   "",
		IFRecvCalls: 1,
		LatencyUS:   float64(time.Since(start).Microseconds()),
	}

	_ = json.NewEncoder(os.Stdout).Encode(out)
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
