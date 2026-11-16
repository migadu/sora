//go:build !unix

package tlsmanager

import (
	"context"
	"fmt"
	"os"
)

func lockLocalEntry(context.Context, *os.Root, string) (func(), error) {
	return nil, fmt.Errorf("local certificate coordination requires Unix")
}
func giveLocalFile(*os.Root, *os.File) error {
	return fmt.Errorf("local certificate coordination requires Unix")
}
func readLocalRegular(*os.Root, string) ([]byte, error) {
	return nil, fmt.Errorf("local certificate coordination requires Unix")
}
