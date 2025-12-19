package main

// NOTE: Go forbids importing a package named "main" (a program) from other packages.
//
// The sora-admin CLI is implemented as package main, so integration tests must
// execute the CLI binary (see integration_tests/imap/shared_mailbox_e2e_test.go)
// instead of importing importer logic directly.
