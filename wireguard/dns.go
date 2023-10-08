package wireguard

import (
	"io"
	"log"
	"net"
	"os"
)

// in a container, /etc/resolv.conf cannot be truncated from the
// beginning as per os.WriteFile, can't be renamed'd etc. but it is writable so
// try to overwrite its contents nicely.
func replaceResolveConf(conf string) (err error) {
	rConfF, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return err
	}
	rConfF.Seek(0, io.SeekStart)
	rConfF.WriteString(conf)
	// if the current resolv.conf is long, this may result in corrupted junk at the end.
	// Look into a way to write nulls or empty spaces or something from the end of the data from nameServers to
	// the end of the file, I guess?

	return nil
}

// Update the system-wide DNS
func (l *Link) dnsSet(addrs []net.IP) (err error) {
	if l.resolvConf, err = os.ReadFile("/etc/resolv.conf"); err != nil {
		log.Println("Link: [ERR] Read /etc/resolv.conf failed")
		return
	}
	if len(l.Config.ResolvConfBackupFile) > 0 { // Backup old resolv.conf if configured to do so
		switch err = os.WriteFile(l.Config.ResolvConfBackupFile, l.resolvConf, 0644); err {
		case nil:
			log.Println("Link: resolv.conf backup in", l.Config.ResolvConfBackupFile)
		default:
			log.Println("Link: [WARN] resolv.conf backup to", l.Config.ResolvConfBackupFile, "failed:", err.Error()) // Backup may fail as the contents of the original resolv.conf are kept in l.resolvConf
		}
	}

	nameServers := "timeout 1\n" // Create new content
	for _, addr := range addrs {
		nameServers += "nameserver " + addr.String() + "\n"
	}

	switch err = os.WriteFile("/etc/resolv.conf", []byte(nameServers), 0644); err { // Update /etc/resolv.conf
	case nil:
		log.Println("Link: /etc/resolv.conf updated")
	default:
		// First try an alternative, in case we're in a container
		log.Println("Link: [WARN] /etc/resolv.conf update failed trying replacing content (maybe we're in a container?)")
		err = replaceResolveConf(nameServers)
		if err != nil {
			log.Println("Link: [ERR] /etc/resolv.conf update failed:", err)
		}
		l.resolvConf = nil // Don't try to restore, it'll just fail. This is a container so assume eventually it'll be cleaned up
	}
	return
}

func (l *Link) dnsRestore() (err error) {
	if l.resolvConf == nil {
		return
	} // No backup taken

	switch err = os.WriteFile("/etc/resolv.conf", l.resolvConf, 0644); err {
	case nil:
		log.Println("Link: /etc/resolv.conf restored")
	default:
		log.Println("Link: [ERR] resolv.conf restore failed:", err.Error())
	}

	if len(l.Config.ResolvConfBackupFile) > 0 {
		switch err = os.Remove(l.Config.ResolvConfBackupFile); err {
		case nil:
			log.Println("Link: resolv.conf backup in", l.Config.ResolvConfBackupFile, "removed")
		default:
			log.Println("Link: [ERR] Removal of", l.Config.ResolvConfBackupFile, "failed, ", err.Error())
		}
	}
	return
}
