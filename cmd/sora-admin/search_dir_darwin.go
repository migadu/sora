package main

// searchDirFlags opens a directory for search only: O_EXEC, which with O_DIRECTORY is
// <fcntl.h>'s O_SEARCH. golang.org/x/sys/unix does not define it for darwin.
const searchDirFlags = 0x40000000
