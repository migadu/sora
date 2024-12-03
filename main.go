package main

import (
	"context"
	"flag"
	"log"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
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

	imapAddr := flag.String("imapaddr", ":143", "IMAP server address")

	// Parse the command-line flags
	flag.Parse()

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
	if *seed {
		log.Println("Seeding the database with test data...")
		err = database.InsertUser(ctx, "user@domain.com", "password")
		if err != nil {
			log.Fatalf("Failed to insert test user: %v", err)
		}
	}

	s, err := server.New(s3storage, database, insecureAuth, debug)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer s.Close()

	log.Println("Starting Sora server...")
	if err := s.Serve(imapAddr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// Implement necessary User methods here
