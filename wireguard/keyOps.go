package wireguard

import (
	"encoding/base64"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Generate a new private key or use the one configured
func ( l *Link ) handlePrivateKey() ( err error ) {
	if len( l.Config.PrivateKey ) == 0 {
		if l.privateKey, err = wgtypes.GeneratePrivateKey(); err != nil { fmt.Println( "Link: [ERR] Generating a new private key failed,", err ); return }
		l.privateKey.PublicKey()
		fmt.Println( "Link: Generated a new wireguard private key" )
	} else {
		privateKeyBytes, err := base64.StdEncoding.DecodeString( l.Config.PrivateKey )
		if err != nil { fmt.Println( "Link: [ERR] Failed while decoding the private key,", err ); return err }
		if l.privateKey, err = wgtypes.NewKey( privateKeyBytes ); err != nil { fmt.Println( "Link: [ERR] Parsing the private key failed,", err ); return err }
		fmt.Println( "Link: Using the configured private key" )
	}
	return
}