package control

import (
	"container/ring"
	"io"
	"sync"
)

type RingLog struct {
	sync.RWMutex
	ring	*ring.Ring
	tee		io.Writer
}

func NewRingLog( lines int, tee io.Writer ) ( r *RingLog ) { return &RingLog{ ring: ring.New( lines ), tee: tee} }

func ( ringLog *RingLog ) Write( b []byte ) ( n int, err error ) {
	if ringLog.tee != nil { n, err = ringLog.tee.Write( b ) }
	ringLog.Lock(); ringLog.ring.Value = string(b); ringLog.ring = ringLog.ring.Next(); ringLog.Unlock()
	return
}

func ( ringLog *RingLog ) Dump() ( b []byte ) {
	b = []byte( nil )
	ringLog.RLock()
	ring := ringLog.ring
	for l := ring.Len(); l > 0 ; l-- {
		if s, ok := ring.Value.( string ); ok { b = append( b, s... ) }
		ring = ring.Next()
	}
	ringLog.RUnlock()
	return
}