#!/bin/bash

# Example of how to run integration tests manually
# This script demonstrates the basic usage

echo "=== SORA Integration Tests Example ==="
echo

# Check if database is available
echo "1. Checking database availability..."
if pg_isready -h localhost -p 5432 -U postgres > /dev/null 2>&1; then
    echo "✓ PostgreSQL is running and accessible"
else
    echo "✗ PostgreSQL is not available"
    echo "  Please start PostgreSQL: brew services start postgresql"
    exit 1
fi

# Check if test database exists
echo "2. Checking test database..."
if psql -h localhost -p 5432 -U postgres -lqt | cut -d \| -f 1 | grep -qw "sora_mail_db"; then
    echo "✓ Test database 'sora_mail_db' exists"
else
    echo "! Creating test database 'sora_mail_db'..."
    createdb -h localhost -p 5432 -U postgres sora_mail_db
    echo "✓ Test database created"
fi

echo
echo "3. Running a single IMAP test as example..."
cd imap
go test -v -tags=integration -run="TestIMAP_LoginAndSelect" -timeout=30s

echo
echo "4. To run all tests, use the main test runner:"
echo "   ./run_integration_tests.sh"
echo
echo "5. To run specific protocol tests:"
echo "   ./run_integration_tests.sh --protocol imap"
echo "   ./run_integration_tests.sh --protocol lmtp"
echo "   ./run_integration_tests.sh --protocol pop3"