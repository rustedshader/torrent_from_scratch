package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/jackpal/bencode-go"
)

func main() {
	data, err := os.ReadFile("./Acc_two.torrent")
	if err != nil {
		panic(err)
	}
	reader := bytes.NewReader(data)
	decoded_data, err := bencode.Decode(reader)
	if err != nil {
		panic(err)
	}
	if announce, ok := decoded_data.(map[string]interface{})["announce"]; ok {
		fmt.Println(announce)
	}
	// if announce_list, ok := decoded_data.(map[string]interface{})["announce-list"]; ok {
	// 	fmt.Println(announce_list)
	// }
	if comment, ok := decoded_data.(map[string]interface{})["comment"]; ok {
		fmt.Println(comment)
	}
	if created_by, ok := decoded_data.(map[string]interface{})["created by"]; ok {
		fmt.Println(created_by)
	}
	if creation_date, ok := decoded_data.(map[string]interface{})["creation date"]; ok {
		fmt.Println(creation_date)
	}
	// if info, ok := decoded_data.(map[string]interface{})["info"]; ok {
	// 	fmt.Println(info)
	// }
	if info, ok := decoded_data.(map[string]interface{})["info"].(map[string]interface{}); ok {
		if name, ok := info["name"]; ok {
			fmt.Println(name)
		}
	}
}
