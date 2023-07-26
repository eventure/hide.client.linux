package control

import "encoding/json"

type Error struct {
	Code	string	`json:"code"`
	Message	string	`json:"message,omitempty"`
}

type Result struct {
	Result	any		`json:"result,omitempty"`
	Error	*Error	`json:"error,omitempty"`
	Id		int		`json:"id,omitempty"`
}

func ( r Result ) Json() ( j []byte ) { j, _ = json.Marshal( r ); return }