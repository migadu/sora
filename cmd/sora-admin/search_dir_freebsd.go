package main

import "golang.org/x/sys/unix"

// searchDirFlags opens a directory for search only.
const searchDirFlags = unix.O_SEARCH
