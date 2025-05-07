package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/jackpal/bencode-go"
)

type TorrentFile struct {
	Announce     string     `bencode:"announce"`
	AnnounceList [][]string `bencode:"announce-list"`
	Comment      string     `bencode:"comment"`
	CreatedBy    string     `bencode:"created by"`
	CreationDate int64      `bencode:"creation date"`
	Encoding     string     `bencode:"encoding"`
	Info         InfoDict   `bencode:"info"`
	Publisher    string     `bencode:"publisher"`
	PublisherURL string     `bencode:"publisher-url"`
}

type InfoDict struct {
	Files       []FileDict `bencode:"files"`
	Name        string     `bencode:"name"`
	PieceLength int64      `bencode:"piece length"`
	Pieces      string     `bencode:"pieces"`
}

type FileDict struct {
	Length int64    `bencode:"length"`
	Path   []string `bencode:"path"`
}

func generateInfoHash(info interface{}) []byte {
	var buf bytes.Buffer
	err := bencode.Marshal(&buf, info)
	if err != nil {
		return nil
	}
	hasher := sha1.New()
	hasher.Write(buf.Bytes())
	return hasher.Sum(nil)
}

func main() {
	data, err := os.ReadFile("./Acc_two.torrent")
	if err != nil {
		panic(err)
	}
	reader := bytes.NewReader(data)
	var tf TorrentFile
	err = bencode.Unmarshal(reader, &tf)
	if err != nil {
		panic(err)
	}
	fmt.Println("Address is ", tf.Announce)
	parsedURL, err := url.Parse(tf.Announce)
	if err != nil {
		fmt.Println("Error parsing announce URL:", err)
	}
	hostAndPort := parsedURL.Host
	fmt.Println("Host is ", hostAndPort)
	udpAddr, err := net.ResolveUDPAddr("udp", hostAndPort)
	if err != nil {
		fmt.Println(err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)

	if err != nil {
		fmt.Println(err)
	}

	defer conn.Close()

	/* Connect Request
	Before announcing or scraping, you have to obtain a connection ID.

	Choose a random transaction ID.
	Fill the connect request structure.
	Send the packet.
	connect request:

	Offset  Size            Name            Value
	0       64-bit integer  protocol_id     0x41727101980 // magic constant
	8       32-bit integer  action          0 // connect
	12      32-bit integer  transaction_id
	16
	Receive the packet.
	Check whether the packet is at least 16 bytes.
	Check whether the transaction ID is equal to the one you chose.
	Check whether the action is connect.
	Store the connection ID for future use.
	connect response:

	Offset  Size            Name            Value
	0       32-bit integer  action          0 // connect
	4       32-bit integer  transaction_id
	8       64-bit integer  connection_id
	16
	*/

	var connectBuf bytes.Buffer
	const protocolID uint64 = 0x41727101980
	connectAction := uint32(0)
	connectTransID := rand.Uint32()

	binary.Write(&connectBuf, binary.BigEndian, protocolID)
	binary.Write(&connectBuf, binary.BigEndian, connectAction)
	binary.Write(&connectBuf, binary.BigEndian, connectTransID)

	_, err = conn.Write(connectBuf.Bytes())
	if err != nil {
		panic(err)
	}

	resp := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(resp)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Transaction Id is: %x\n", connectTransID)
	fmt.Printf("Recieved Data is: %x\n", resp)
	recieved_action := resp[:4]
	recieved_transaction_id := resp[4:8]
	recieved_connection_id := resp[8:]
	if binary.BigEndian.Uint32(recieved_transaction_id) != connectTransID {
		fmt.Printf("Transaction ID did not match !\n")
	}
	fmt.Printf("Recieved Sent Action was: %x\n", recieved_action)
	fmt.Printf("Recieved Transaction Id is: %x\n", recieved_transaction_id)
	fmt.Printf("Recieved Connection Id is %x\n", recieved_connection_id)

	/* Announce Request

	Choose a random transaction ID.
	Fill the announce request structure.
	Send the packet.
	IPv4 announce request:

	Offset  Size    Name    Value
	0       64-bit integer  connection_id
	8       32-bit integer  action          1 // announce
	12      32-bit integer  transaction_id
	16      20-byte string  info_hash
	36      20-byte string  peer_id
	56      64-bit integer  downloaded
	64      64-bit integer  left
	72      64-bit integer  uploaded
	80      32-bit integer  event           0 // 0: none; 1: completed; 2: started; 3: stopped
	84      32-bit integer  IP address      0 // default
	88      32-bit integer  key
	92      32-bit integer  num_want        -1 // default
	96      16-bit integer  port
	98
	Receive the packet.
	Check whether the packet is at least 20 bytes.
	Check whether the transaction ID is equal to the one you chose.
	Check whether the action is announce.
	Do not announce again until interval seconds have passed or an event has occurred.
	Do note that most trackers will only honor the IP address field under limited circumstances.

	IPv4 announce response:

	Offset      Size            Name            Value
	0           32-bit integer  action          1 // announce
	4           32-bit integer  transaction_id
	8           32-bit integer  interval
	12          32-bit integer  leechers
	16          32-bit integer  seeders
	20 + 6 * n  32-bit integer  IP address
	24 + 6 * n  16-bit integer  TCP port
	20 + 6 * N
	*/

	var announceBuf bytes.Buffer
	connectionId := binary.BigEndian.Uint64(recieved_connection_id)
	announceAction := uint32(1)
	announceTransactionId := rand.Uint32()
	info_hash := generateInfoHash(tf.Info)
	prefix := "-GO-"
	var peerId [20]byte
	copy(peerId[:], []byte(prefix))
	downloaded := uint64(0)
	left := uint64(tf.Info.PieceLength)
	uploaded := uint64(0)
	event := uint32(0)
	ip := uint32(0)
	key := rand.Uint32()
	num_want := uint32(0xFFFFFFFF) // -1 in unsigned 32-bit integer representation
	port := uint16(6881)

	binary.Write(&announceBuf, binary.BigEndian, connectionId)
	binary.Write(&announceBuf, binary.BigEndian, announceAction)
	binary.Write(&announceBuf, binary.BigEndian, announceTransactionId)
	binary.Write(&announceBuf, binary.BigEndian, info_hash)
	binary.Write(&announceBuf, binary.BigEndian, peerId)
	binary.Write(&announceBuf, binary.BigEndian, downloaded)
	binary.Write(&announceBuf, binary.BigEndian, left)
	binary.Write(&announceBuf, binary.BigEndian, uploaded)
	binary.Write(&announceBuf, binary.BigEndian, event)
	binary.Write(&announceBuf, binary.BigEndian, ip)
	binary.Write(&announceBuf, binary.BigEndian, key)
	binary.Write(&announceBuf, binary.BigEndian, num_want)
	binary.Write(&announceBuf, binary.BigEndian, port)

	_, err = conn.Write(announceBuf.Bytes())
	if err != nil {
		panic(err)
	}
	announceResp := make([]byte, 20)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(announceResp)
	if err != nil {
		panic(err)
	}

	recieved_announce_action := announceResp[:4]
	recieved_announce_transaction_id := announceResp[4:8]
	recieved_announce_interval := announceResp[8:12]
	recieved_announce_leechers := announceResp[12:16]
	recieved_announce_seeders := announceResp[16:20]

	fmt.Printf("My Announce Transaction Id is: %x\n", announceTransactionId)
	fmt.Printf("Tracker Announce Transaction Id is: %x\n", recieved_announce_transaction_id)
	fmt.Printf("Tracker Announce Action: %x\n", recieved_announce_action)
	fmt.Printf("Tracker Announce Interval is: %x\n", recieved_announce_interval)
	fmt.Printf("Tracker Announce Leechers is: %x\n", recieved_announce_leechers)
	fmt.Printf("Tracker Announce Seeders is: %x\n", recieved_announce_seeders)
	fmt.Printf("Tracker rest is: %x\n", announceResp[20:])

}
