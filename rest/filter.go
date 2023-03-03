package rest

import (
	"errors"
	"strconv"
	"strings"
)

type Filter struct {
	Ads			bool		`yaml:"ads,omitempty"`
	Trackers	bool		`yaml:"trackers,omitempty"`
	Malicious	bool		`yaml:"malicious,omitempty"`
	PG			int			`yaml:"PG,omitempty"`
	SafeSearch	bool		`yaml:"safeSearch,omitempty"`
	Categories	string		`yaml:"categories,omitempty"`
}

func (f *Filter) Empty() bool {
	if f.Ads || f.Trackers || f.Malicious || f.SafeSearch { return false }
	if f.PG > 0 { return false }
	if len(f.Categories) > 0 { return false }
	return true
}

func (f *Filter) String() ( pretty string ) {
	if f.Ads				 { pretty += ", ads" }
	if f.Trackers			 { pretty += ", trackers" }
	if f.Malicious			 { pretty += ", malicious" }
	if f.PG > 0				 { pretty += ", pg-" + strconv.Itoa( f.PG ) }
	if f.SafeSearch			 { pretty += ", safe search" }
	if len(f.Categories) > 0 { pretty += "; " + f.Categories }
	pretty = strings.TrimPrefix( pretty, ", " )
	return
}

func (f *Filter) ToRequest() ( request *FilterRequest ) {
	request = &FilterRequest{
		Ads:        f.Ads,
		Trackers:   f.Trackers,
		Malicious:  f.Malicious,
		PG:         f.PG,
		SafeSearch: f.SafeSearch,
	}
	if len( f.Categories ) > 0 { request.Categories = strings.Split( f.Categories, "," ) }
	return
}

type FilterRequest struct {
	Ads			bool		`json:"ads,omitempty"`
	Trackers	bool		`json:"trackers,omitempty"`
	Malicious	bool		`json:"malicious,omitempty"`
	PG			int			`json:"PG,omitempty"`
	SafeSearch	bool		`json:"safeSearch,omitempty"`
	Categories	[]string	`json:"categories,omitempty"`
}

func (f *FilterRequest) Check() error {
	switch f.PG {
		case 0, 12, 18, 21: break
		default: return errors.New( "unsupported PG" )
	}
	return nil
}