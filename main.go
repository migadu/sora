package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

func main() {
	seed := flag.Bool("seed", false, "Insert seed data into the database")
	insecureAuth := flag.Bool("insecure-auth", false, "Allow authentication without TLS")
	debug := flag.Bool("debug", false, "Print all commands and responses")

	// Define command-line flags for database and S3 credentials
	dbHost := flag.String("dbhost", "localhost", "Database host")
	dbPort := flag.String("dbport", "5432", "Database port")
	dbUser := flag.String("dbuser", "postgres", "Database user")
	dbPassword := flag.String("dbpassword", "", "Database password (can be empty for local development)")
	dbName := flag.String("dbname", "imap_db", "Database name")

	s3Endpoint := flag.String("s3endpoint", "", "S3 endpoint")
	s3AccessKey := flag.String("s3accesskey", "", "S3 access key")
	s3SecretKey := flag.String("s3secretkey", "", "S3 secret key")
	s3Bucket := flag.String("s3bucket", "", "S3 bucket name")

	startImap := flag.Bool("imap", true, "Start the IMAP server")
	imapAddr := flag.String("imapaddr", ":143", "IMAP server address")
	startLmtp := flag.Bool("lmtp", true, "Start the LMTP server")
	lmtpAddr := flag.String("lmtpaddr", ":24", "LMTP server address")
	startPop3 := flag.Bool("pop3", true, "Start the POP3 server")
	pop3Addr := flag.String("pop3addr", ":110", "POP3 server address")

	// Parse the command-line flags
	flag.Parse()

	if !*startImap && !*startLmtp && !*startPop3 {
		log.Fatal("No servers enabled. Please enable at least one server (IMAP, LMTP, or POP3).")
	}

	// Ensure required arguments are provided
	if *s3AccessKey == "" || *s3SecretKey == "" || *s3Bucket == "" {
		log.Fatal("Missing required credentials. Ensure S3 access key, secret key, and bucket are provided.")
	}

	// Initialize S3 storage
	log.Printf("Connecting to S3 endpoint %s, bucket %s", *s3Endpoint, *s3Bucket)
	s3storage, err := storage.NewS3Storage(*s3Endpoint, *s3AccessKey, *s3SecretKey, *s3Bucket, true)
	if err != nil {
		log.Fatalf("Failed to initialize S3 storage at endpoint %s: %v", *s3Endpoint, err)
	}

	// Initialize the database connection
	ctx := context.Background()
	log.Printf("Connecting to database at %s:%s as user %s, using database %s", *dbHost, *dbPort, *dbUser, *dbName)
	database, err := db.NewDatabase(ctx, *dbHost, *dbPort, *dbUser, *dbPassword, *dbName)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer database.Close() // Ensure the database is closed on exit

	// If the seed flag is set, insert test data
	// TODO: Remove this in production
	if *seed {
		log.Println("Seeding the database with test data...")
		err = database.InsertUser(ctx, "user@domain.com", "password")
		if err != nil {
			log.Fatalf("Failed to insert test user: %v", err)
		}
	}

	hostname, _ := os.Hostname()

	errChan := make(chan error, 1)

	// Start LMTP server
	if *startLmtp {
		go startLMTPServer(hostname, *lmtpAddr, s3storage, database, *debug, errChan)
	}

	// Start IMAP server
	if *startImap {
		go startIMAPServer(hostname, *imapAddr, s3storage, database, *insecureAuth, *debug, errChan)
	}

	// Start POP3 server
	if *startPop3 {
		go startPOP3Server(hostname, *pop3Addr, s3storage, database, *insecureAuth, *debug, errChan)
	}

	// Wait for any errors from the servers
	if err := <-errChan; err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func startIMAPServer(hostname, addr string, s3storage *storage.S3Storage, database *db.Database, insecureAuth bool, debug bool, errChan chan error) {
	s, err := imap.New(hostname, addr, s3storage, database, insecureAuth, debug)
	if err != nil {
		log.Fatalf("Failed to start IMAP server: %v", err)
	}
	defer s.Close()
	if err := s.Serve(addr); err != nil {
		errChan <- err
	}
}

func startLMTPServer(hostname, addr string, s3storage *storage.S3Storage, database *db.Database, debug bool, errChan chan error) {
	s := lmtp.New(hostname, addr, s3storage, database, debug, errChan)
	defer s.Close()
}

func startPOP3Server(hostname string, addr string, s3storage *storage.S3Storage, database *db.Database, insecureAuth bool, debug bool, errChan chan error) {
	s, err := pop3.New(hostname, addr, s3storage, database, insecureAuth, debug)
	if err != nil {
		log.Fatalf("Failed to start POP3 server: %v", err)
	}
	defer s.Close()
	s.Start(errChan)
}
