package wireguard

import (
	"encoding/base64"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log"
)

// Generate a new private key or use the one configured
func ( l *Link ) handlePrivateKey() ( err error ) {
	if len( l.Config.PrivateKey ) == 0 {
		if l.privateKey, err = wgtypes.GeneratePrivateKey(); err != nil { log.Println( "Link: [ERR] Generate private key failed:", err ); return }
		log.Println( "Link: Generated a new wireguard private key" )
	} else {
		privateKeyBytes, err := base64.StdEncoding.DecodeString( l.Config.PrivateKey )
		if err != nil { log.Println( "Link: [ERR] Decode private key failed:", err ); return err }
		if l.privateKey, err = wgtypes.NewKey( privateKeyBytes ); err != nil { log.Println( "Link: [ERR] Private key parse failed:", err ); return err }
		log.Println( "Link: Using the configured private key" )
	}
	return
}