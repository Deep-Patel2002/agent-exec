//go:build !windows

package api

import (
	"errors"
	"os"
)

func checkPrivateFile(info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("token database must not be accessible to group or other users")
	}
	return nil
}
