package wireguard

import (
	"log"
	"net"
	"os"
)

// Update the system-wide DNS
func (l *Link) dnsSet( addrs []net.IP ) ( err error ) {
	if l.resolvConf, err = os.ReadFile( "/etc/resolv.conf" ); err != nil { log.Println( "Link: [ERR] Read /etc/resolv.conf failed" ); return }
	if len( l.Config.ResolvConfBackupFile ) > 0 {																										// Backup old resolv.conf if configured to do so
		switch err = os.WriteFile( l.Config.ResolvConfBackupFile, l.resolvConf, 0644 ); err {
			case nil: log.Println( "Link: resolv.conf backup in", l.Config.ResolvConfBackupFile )
			default:  log.Println( "Link: [WARN] resolv.conf backup to", l.Config.ResolvConfBackupFile, "failed:", err.Error() )						// Backup may fail as the contents of the original resolv.conf are kept in l.resolvConf
		}
	}
	
	nameServers := "timeout 1\n"																														// Create new content
	for _, addr := range addrs { nameServers += "nameserver " + addr.String() + "\n" }
	
	switch err = os.WriteFile( "/etc/resolv.conf", []byte( nameServers ), 0644 ); err {																	// Update /etc/resolv.conf
		case nil: log.Println( "Link: /etc/resolv.conf updated" )
		default:  log.Println( "Link: [ERR] /etc/resolv.conf update failed:", err )
	}
	return
}

func (l *Link) dnsRestore() ( err error ) {
	if l.resolvConf == nil { return }																													// No backup taken
	
	switch err = os.WriteFile( "/etc/resolv.conf", l.resolvConf, 0644 ); err {
		case nil: log.Println( "Link: /etc/resolv.conf restored" )
		default:  log.Println( "Link: [ERR] resolv.conf restore failed:", err.Error() )
	}
	
	if len( l.Config.ResolvConfBackupFile ) > 0 {
		switch err = os.Remove( l.Config.ResolvConfBackupFile ); err {
			case nil: log.Println( "Link: resolv.conf backup in", l.Config.ResolvConfBackupFile, "removed" )
			default:  log.Println( "Link: [ERR] Removal of", l.Config.ResolvConfBackupFile, "failed, ", err.Error() )
		}
	}
	return
}