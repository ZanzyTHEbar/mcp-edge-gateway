//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package credentialbridge

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// DisableCoreDumps prevents this executable and its keystore helpers from
// writing token-bearing process memory into a filesystem core dump.
func DisableCoreDumps() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

func tryFileLock(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return err == nil, err
}

func releaseFileLock(file *os.File) { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }
