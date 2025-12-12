package rest

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var nameRegexp = regexp.MustCompile( `^([[:word:]]|\x2E|\x2D|\x2A)+$` )									// [0-9A-Za-z_] | "." | "-" | "*"

type Filter struct {
	AccessToken	[]byte		`yaml:"accessToken,omitempty" json:"accessToken,omitempty"`
	ForceDns	bool		`yaml:"forceDns,omitempty" json:"forceDns,omitempty"`
	Ads			bool		`yaml:"ads,omitempty" json:"ads,omitempty"`
	Trackers	bool		`yaml:"trackers,omitempty" json:"trackers,omitempty"`
	Malware		bool		`yaml:"malware,omitempty" json:"malware,omitempty"`
	SafeSearch	bool		`yaml:"safeSearch,omitempty" json:"safeSearch,omitempty"`
	PG			int			`yaml:"PG,omitempty" json:"PG,omitempty"`
	Malicious	bool		`yaml:"malicious,omitempty" json:"malicious,omitempty"`
	Risk		[]string	`yaml:"risk,omitempty" json:"risk,omitempty"`
	Illegal		[]string	`yaml:"illegal,omitempty" json:"illegal,omitempty"`
	Whitelist	[]string	`yaml:"whitelist,omitempty" json:"whitelist,omitempty"`
	Blacklist	[]string	`yaml:"blacklist,omitempty" json:"blacklist,omitempty"`
	Categories	[]string	`yaml:"categories,omitempty" json:"categories,omitempty"`
}

func (f *Filter) Empty() bool {
	if f.ForceDns || f.Ads || f.Trackers || f.Malware || f.Malicious || f.SafeSearch { return false }
	if f.PG > 0 { return false }
	if len(f.Categories) > 0 { return false }
	if len(f.Risk) > 0 { return false }
	if len(f.Illegal) > 0 { return false }
	if len(f.Whitelist) > 0 { return false }
	if len(f.Blacklist) > 0 { return false }
	return true
}

func (f *Filter) String() ( pretty string ) {
	if f.ForceDns			 { pretty += ", forceDns" }
	if f.Ads				 { pretty += ", ads" }
	if f.Trackers			 { pretty += ", trackers" }
	if f.Malware			 { pretty += ", malware" }
	if f.SafeSearch			 { pretty += ", safe search" }
	if f.PG > 0				 { pretty += ", pg-" + strconv.Itoa( f.PG ) }
	if f.Malicious			 { pretty += ", malicious" }
	if len(f.Risk) > 0		 { pretty += ", risk=" + strings.Join( f.Risk, "," ) }
	if len(f.Illegal) > 0	 { pretty += ", illegal=" + strings.Join( f.Illegal, "," ) }
	if len(f.Whitelist) > 0	 { pretty += ", whitelist=" + strings.Join( f.Whitelist, "," ) }
	if len(f.Blacklist) > 0	 { pretty += ", blacklist=" + strings.Join( f.Blacklist, "," ) }
	if len(f.Categories) > 0 { pretty += ", categories=" + strings.Join( f.Categories, "," ) }
	pretty = strings.TrimPrefix( pretty, ", " )
	return
}

func (f *Filter) Check() error {
	switch f.PG {
		case 0, 12, 18, 21: break
		default: return errors.New( "unsupported PG" )
	}
	for _, risk := range f.Risk {
		switch risk {
			case "", "possible", "medium", "high": break
			default: return errors.New( "unsupported risk level " + risk )
		}
	}
	for _, illegal := range f.Illegal {
		switch illegal {
			case "", "content", "warez", "spyware", "copyright": break
			default: return errors.New( "bad illegal category " + illegal )
		}
	}
	for _, name := range f.Whitelist { if !nameRegexp.MatchString( name ) { return errors.New( "bad DNS name " + name ) } }
	for _, name := range f.Blacklist { if !nameRegexp.MatchString( name ) { return errors.New( "bad DNS name " + name ) } }

	return nil
}