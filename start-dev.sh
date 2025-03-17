#!/bin/sh
go run -race main.go \
-insecure-auth \
-imap -imapaddr localhost:1143 \
-lmtp=false -pop3=false \
-s3accesskey 003a3c9fd5080460000000004 -s3bucket imap-test -s3secretkey K003oQbwgXVgeEYnhXEgZPYp22IH4zU -s3endpoint s3.eu-central-003.backblazeb2.com \
-dbhost 127.0.0.1 -seed \
-debug
