/*
Copyright (C) <2021-2022>  <Marius Genheimer>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.
You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
*/

package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// base64Decode decodes base64 data passed as a byte array; returns a byte array
func base64Decode(message []byte) (b []byte) {
	b = make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, base64Err := base64.StdEncoding.Decode(b, message)
	check(base64Err)
	return b[:l]
}

// check if a string contains valid base64 encoded data
func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func AES128ECB(data, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}

func decryptMessage(msg string) string {
	// decode the b64 encoded message
	decoded := base64Decode([]byte(msg))
	// decode the AES Key extracted from the loaded config file
	aesKey, hexErr := hex.DecodeString(config.Landing.Key)
	check(hexErr)
	// decrypt the message with AES ECB
	decrypted := AES128ECB(decoded, aesKey)
	return string(decrypted)
}

func c2Handler(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		timeS := time.Now()
		// Call ParseForm() to parse the raw query and update r.PostForm and r.Form.
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}

		color.Blue("→ New POST request:")

		// some useful meta data of the request
		var mData Meta

		if jsonFlag {
			mData.TimeStamp = timeS
			mData.URI = r.RequestURI
			mData.Host = r.Host
			mData.Remote = r.RemoteAddr
			mData.UserAgent = r.UserAgent()
			mData.ContentLength = int(r.ContentLength)
			mData.ContentType = r.Header.Get("Content-Type")
		}

		w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
		fmt.Fprintln(w1, "URI: \t", mData.URI)
		fmt.Fprintln(w1, "Host: \t", mData.Host)
		fmt.Fprintln(w1, "Remote: \t", mData.Remote)
		fmt.Fprintln(w1, "User-Agent: \t", mData.UserAgent)
		fmt.Fprintln(w1, "Content-Length: \t", mData.ContentLength)
		fmt.Fprintln(w1, "Content-Type: \t", mData.ContentType)
		w1.Flush()

		var status string

		// loop through the form values and find the base64 encoded + encrypted status blob
		for k := range r.Form {
			status = r.FormValue(k)
			if len(status) > 64 && isBase64(status) {
				break
			}
		}

		// decrypt the message and print it to stdout
		color.Green("\n✓ Decrypted message:\n")
		decrypted := decryptMessage(status)
		fmt.Printf("%v\n", decrypted)

		// remove garbage from decrypted message
		decrypted = strings.Replace(decrypted, "\u000a", "", -1)
		decrypted = strings.TrimFunc(decrypted, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})

		var resp string
		var JsonInfo C2Info
		var JsonStats C2Stats
		var jsonBytes []byte
		var marshalErr error

		color.Yellow("→ Response:\n")

		filename := "fakematter-" + timeS.Format("20060102150405") + ".json"

		if strings.Contains(decrypted, "disks_info") {
			if jsonFlag {
				JsonInfo.MetaData = mData

				unmarshalErr := json.Unmarshal([]byte(decrypted), &JsonInfo.Info)
				check(unmarshalErr)

				jsonBytes, marshalErr = json.Marshal(JsonInfo)
				check(marshalErr)
			}

			resp = "{\"qWmps\":\"FJEWgL39\",\"J7vQt6pD\":\"bEppWkl\",\"lmOaPBCYM\":\"9iFUT89\"}"
		} else {
			if jsonFlag {
				JsonStats.MetaData = mData

				unmarshalErr := json.Unmarshal([]byte(decrypted), &JsonStats.Stats)
				check(unmarshalErr)

				jsonBytes, marshalErr = json.Marshal(JsonStats)
				check(marshalErr)
			}

			resp = "{\"RGBCaI2\":\"Ofho9MOCeL\",\"BGhc2RK8lR\":\"nKtszgDe\",\"TSbCSavlQ2\":\"GH0hArU\",\"sUAw4ICL\":\"z1NSuDDA\"}"
		}

		if jsonFlag {
			// replace unicode ampersand in JSON string
			pattern, hexErr := hex.DecodeString("5c7530303236")
			check(hexErr)
			jsonBytes = bytes.Replace(jsonBytes, pattern, []byte("&"), -1)

			// write the JSON string to the output file
			writeErr := ioutil.WriteFile(filename, jsonBytes, 0644)
			check(writeErr)
		}

		// ┌───────────┐
		// │ Response  │
		// └───────────┘

		// print to stdout
		fmt.Printf("%v\n\n", resp)
		// HTTP response
		fmt.Fprintf(w, "%v", resp)
	}
}

var (
	deviceName  string          // will be defined through the CLI flag
	snapshotLen uint32 = 262144 // The same default as tcpdump
	promiscuous bool   = false  // disable promiscuous mode as we don't need it here
	pcapErr     error
	handle      *pcap.Handle
	packetCount int = 0
	packetLimit int = 1024
)

func runPacketCapture() {
	// Open output pcap file and write header
	pcapName := "fakematter-" + time.Now().Format("20060102150405") + ".pcap"
	f, _ := os.Create(pcapName)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	defer f.Close()

	// Open the device for capturing
	handle, pcapErr = pcap.OpenLive(deviceName, int32(snapshotLen), promiscuous, pcap.BlockForever)
	check(pcapErr)
	defer handle.Close()

	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Process packet here
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++

		// stop capturing packet
		if packetCount > packetLimit {
			break
		}
	}
	color.HiMagenta("→ Timeout, captured %v packets. Stopping.\n", packetCount)
}

// Flag variables for commandline arguments
var portFlag string
var ifaceFlag string
var jsonFlag bool

// struct to store the configuration of the ransomware
var config BlackmatterConfig

func main() {

	fmt.Printf("\n             *       +")
	fmt.Printf("\n       '                  |           __       _                        _   _  ")
	fmt.Printf("\n   ()    .-.,=''''=.    - o -        / _| __ _| | _____ _ __ ___   __ _| |_| |_ ___ _ __ ")
	fmt.Printf("\n         '=/_       \\     |         | |_ / _` | |/ / _ \\ '_ ` _ \\ / _` | __| __/ _ \\ '__|")
	fmt.Printf("\n      *   |  '=._    |              |  _| (_| |   <  __/ | | | | | (_| | |_| ||  __/ |   ")
	fmt.Printf("\n           \\     `=./`,        '    |_|  \\__,_|_|\\_\\___|_| |_| |_|\\__,_|\\__|\\__\\___|_|   ")
	fmt.Printf("\n        .   '=.__.=' `='      *")
	fmt.Printf("\n  +                       +         BlackMatter Linux Ransomware C2 Emulator and Analyzer")
	fmt.Printf("\n    O      *        '       .       Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	// parse passed flags
	flag.StringVar(&portFlag, "port", "80", "Specify the port to listen on. Default: Port 80. Make sure you have the required permissions and there are no other services running on this port.")
	flag.StringVar(&ifaceFlag, "iface", "", "Interface to use for packet capture. Make sure you have the required permissions.")
	flag.BoolVar(&jsonFlag, "j", false, "Write extracted messages to a JSON file")
	flag.Parse()

	if flag.NArg() == 0 {
		color.Red("✗ No path to config file provided.\n\n")
		os.Exit(1)
	}

	cfgJSON, readErr := ioutil.ReadFile(flag.Args()[0])
	check(readErr)

	// unmarshal the decrypted config into the struct
	jsonErr := json.Unmarshal(cfgJSON, &config)
	check(jsonErr)

	if ifaceFlag != "" {
		color.Cyan("→ Starting packet capture on interface %v\n", ifaceFlag)
		deviceName = ifaceFlag
		go runPacketCapture()
	}

	http.HandleFunc("/", c2Handler)

	color.Cyan("→ Starting fakematter server on port %v\n\n", portFlag)
	if httpErr := http.ListenAndServe(":"+portFlag, nil); httpErr != nil {
		log.Fatal(httpErr)
	}
}
