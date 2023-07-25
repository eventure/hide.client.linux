package wireguard

import (
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"time"
)

// Configure the wireguard interface with the private key and the listen port
func ( l *Link ) wgLinkUp() ( err error ) {
	wgConfig := wgtypes.Config{
		PrivateKey:	&l.privateKey,
		ListenPort:	&l.Config.ListenPort,
	}
	if l.Config.FirewallMark > 0 { wgConfig.FirewallMark = &l.Config.FirewallMark }
	err = l.wgClient.ConfigureDevice( l.Config.Name, wgConfig )
	if err != nil { fmt.Println( "Link: [ERR] Wireguard device", l.Config.Name, "configuration failed,", err ); return }
	fmt.Println( "Link: Wireguard device", l.Config.Name, "configured" )
	return
}

// Create a peer
func ( l *Link ) wgAddPeer( publicKeyBytes []byte, presharedKeyBytes []byte, endpoint net.UDPAddr, persistentKeepaliveInterval time.Duration ) ( err error ) {
	publicKey, err := wgtypes.NewKey( publicKeyBytes )																	// Parse the public key
	if err != nil { fmt.Println( "Link: [ERR] Parsing the public key for", endpoint.String(), "failed,", err ); return }
	var presharedKey wgtypes.Key
	if len( presharedKeyBytes ) > 0 {																					// Parse the preshared key ( if any )
		if presharedKey, err = wgtypes.NewKey( presharedKeyBytes ); err != nil { return }
	}
	
	l.peer = wgtypes.PeerConfig {																						// Peer configuration
		PublicKey:						publicKey,
		PresharedKey:					&presharedKey,
		Endpoint:						&endpoint,
		PersistentKeepaliveInterval:	&persistentKeepaliveInterval,
		ReplaceAllowedIPs:				true,
		AllowedIPs:						[]net.IPNet {
											{ IP: net.ParseIP( "0.0.0.0" ), Mask: net.CIDRMask( 0, 32 ) },				// IPv4 default route
											{ IP: net.ParseIP("::"), Mask: net.CIDRMask(0, 128) },						// IPv6 default route
										},
	}
	err = l.wgClient.ConfigureDevice( l.Config.Name, wgtypes.Config{
		ReplacePeers:	true,
		Peers:			[]wgtypes.PeerConfig{ l.peer },
	})
	if err != nil { fmt.Println( "Link: [ERR] Wireguard device", l.Config.Name, "configuration failed,", err ); return }
	fmt.Println( "Link: Peer", endpoint.String(), "added" )
	return
}

// Remove the already configured and active peer
func ( l *Link ) wgRemovePeer() ( err error ) {
	l.peer.Remove = true
	err = l.wgClient.ConfigureDevice( l.Config.Name, wgtypes.Config{
		ReplacePeers:	true,
		Peers:			[]wgtypes.PeerConfig{ l.peer },
	})
	if err != nil { fmt.Println( "Link: [ERR] Wireguard device", l.Config.Name, "configuration failed,", err ); return }
	fmt.Println( "Link: Peer", l.peer.Endpoint.String(), "removed" )
	return
}

// Acct fetches the traffic counters
func ( l *Link ) Acct() ( rxBytes, txBytes int64, err error ) {
	device, err := l.wgClient.Device( l.Config.Name )
	if err != nil { return }
	for _, peer := range device.Peers {
		rxBytes += peer.ReceiveBytes
		txBytes += peer.TransmitBytes
	}
	return
}

// GetRx fetches the RX traffic counter
func ( l *Link ) GetRx() ( currentRx int64, err error ) {
	device, err := l.wgClient.Device( l.Config.Name )
	if err != nil { fmt.Println( "Link: [ERR] Wireguard device", l.Config.Name, "failed,", err ); return 0, err }
	if len( device.Peers ) != 1 { fmt.Println( "Link: [ERR] More than one peer on interface", l.Config.Name ); return 0, errors.New( "multiple peers on a single wireguard device" ) }
	return device.Peers[0].ReceiveBytes, nil
}