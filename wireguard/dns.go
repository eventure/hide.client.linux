package wireguard

import (
	"golang.org/x/sys/unix"
	"io"
	"log"
	"net"
	"os"
)

// Update the system-wide DNS
func (l *Link) dnsSet( addrs []net.IP ) ( err error ) {
	file, err := os.OpenFile( "/etc/resolv.conf", os.O_RDWR, 0644 )																						// Open /etc/resolv.conf
	if err != nil { log.Println( "Link: [ERR] Open /etc/resolv.conf failed" ); return }
	if l.resolvConf, err = io.ReadAll( file ); err != nil { log.Println( "Link: [ERR] Read /etc/resolv.conf failed" ); return }
	if len( l.Config.ResolvConfBackupFile ) > 0 {																										// Backup old resolv.conf if configured to do so
		switch err = os.WriteFile( l.Config.ResolvConfBackupFile, l.resolvConf, 0644 ); err {
			case nil: log.Println( "Link: resolv.conf backup in", l.Config.ResolvConfBackupFile )
			default:  log.Println( "Link: [WARN] resolv.conf backup to", l.Config.ResolvConfBackupFile, "failed:", err.Error() )						// Backup may fai. The contents of the original resolv.conf are kept in l.resolvConf and can be restored
		}
	}

	nameServers := "timeout 1\n"																														// Create new content
	for _, addr := range addrs { nameServers += "nameserver " + addr.String() + "\n" }
	
	if _, err = file.Seek( 0, unix.SEEK_SET ); err != nil { log.Println( "Link: [ERR] Seek in /etc/resolv.conf failed" ); return }						// Seek to start
	if _, err = file.WriteString( nameServers ); err != nil { log.Println( "Link: [ERR] /etc/resolv.conf update failed" ); return }						// Update
	if err = file.Truncate( int64( len( nameServers ) ) ); err != nil { log.Println( "Link: [WARN] Truncate /etc/resolv.conf failed" ) }				// Truncate resolv.conf
	log.Println( "Link: /etc/resolv.conf updated" )

	return
}

func (l *Link) dnsRestore() ( err error ) {
	if l.resolvConf == nil { return }																													// No backup taken

	file, err := os.OpenFile( "/etc/resolv.conf", os.O_RDWR, 0644 )																						// Open /etc/resolv.conf
	if err != nil { log.Println( "Link: [ERR] Open /etc/resolv.conf failed" ); return }
	if _, err = file.Seek( 0, unix.SEEK_SET ); err != nil { log.Println( "Link: [ERR] Seek in /etc/resolv.conf failed" ); return }						// Seek to start
	if _, err = file.Write( l.resolvConf ); err != nil { log.Println( "Link: [WARN] /etc/resolv.conf restore failed" ); return }						// Update
	if err = file.Truncate( int64( len( l.resolvConf ) ) ); err != nil { log.Println( "Link: [WARN] Truncate /etc/resolv.conf failed" ) }				// Truncate resolv.conf
	log.Println( "Link: /etc/resolv.conf restored" )

	if len( l.Config.ResolvConfBackupFile ) > 0 {
		switch err = os.Remove( l.Config.ResolvConfBackupFile ); err {
			case nil: log.Println( "Link: resolv.conf backup in", l.Config.ResolvConfBackupFile, "removed" )
			default:  log.Println( "Link: [ERR] Removal of", l.Config.ResolvConfBackupFile, "failed, ", err.Error() )
		}
	}
	return
}