package main

import "golang.org/x/sys/unix"

// searchDirFlags opens a directory for search only: an O_PATH descriptor names the
// entries below it for the *at calls without read permission on the directory.
const searchDirFlags = unix.O_PATH
