//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package credentialbridge

import (
	"errors"
	"os"
)

func DisableCoreDumps() error { return errors.New("credential bridge requires Unix process hardening") }

func tryFileLock(*os.File) (bool, error) {
	return false, errors.New("credential bridge requires Unix file locking on this platform")
}
func releaseFileLock(*os.File) {}
