package doh

import "strconv"

type ErrHttpStatus int
func ( e ErrHttpStatus ) Error() string { return "bad HTTP status " + strconv.Itoa( int( e ) ) }