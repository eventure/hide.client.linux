package wireguard

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrTooManyPeers = errors.New( "multiple peers on a single wireguard device" )
	ErrDpdTimeout = errors.New( "dpd timeout" )
)

func ( l *Link ) DPD( ctx context.Context ) error {
	var tickerChannel <- chan time.Time
	if l.Config.DpdTimeout > 0 {
		ticker := time.NewTicker( l.Config.DpdTimeout )
		defer ticker.Stop()
		tickerChannel = ticker.C
	}
	doneChannel := ctx.Done()
	lastRx := int64( 0 )
	
	fmt.Println( "Link: DPD starting")
	for {
		select {
			case <-tickerChannel: break
			case <-doneChannel: fmt.Println( "Link: DPD stopped" ); return ctx.Err()
		}
		device, err := l.wgClient.Device( l.Config.Name )
		if err != nil { fmt.Println( "Link: [ERR] Wireguard device", l.Config.Name, "failed,", err ); return err }
		if len( device.Peers ) != 1 { fmt.Println( "Link: [ERR] More than one peer on interface", l.Config.Name ); return ErrTooManyPeers }
		currentRx := device.Peers[0].ReceiveBytes
		if currentRx == lastRx { fmt.Println( "Link: [DPD] No incoming traffic seen in last", l.Config.DpdTimeout ); return ErrDpdTimeout }
		lastRx = currentRx
	}
}
