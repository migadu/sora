#!/bin/bash

# Performance Testing Script for Sora Search Functionality
# This script demonstrates how to run the comprehensive performance tests

set -e

echo "🚀 Sora Search Performance Testing"
echo "=================================="

# Check if config-test.toml exists
if [ ! -f "config-test.toml" ]; then
    echo "❌ config-test.toml not found. Please create it first."
    echo "   Copy config.toml.example to config-test.toml and configure for your test database."
    exit 1
fi

echo "✅ Found config-test.toml"

# Check if PostgreSQL is accessible
if ! command -v psql &> /dev/null; then
    echo "⚠️  psql not found in PATH. Make sure PostgreSQL client is installed."
fi

echo ""
echo "📊 Running Search Performance Tests"
echo "-----------------------------------"

# Run basic search tests (quick)
echo "1. Basic search functionality tests..."
go test -v ./db -run "TestSearchConstants|TestSearchCriteriaValidation" -timeout 30s

echo ""
echo "2. Search validation tests..."
go test -v ./db -run "TestValidate" -timeout 30s

echo ""
echo "3. Basic search performance tests..."
go test -v ./db -run "TestSearchPerformanceBasic" -timeout 60s

echo ""
echo "🎯 Comprehensive Performance Tests"
echo "----------------------------------"
echo "Note: These tests create large datasets and may take several minutes"

# Prompt user for comprehensive tests
read -p "Run comprehensive performance tests with large datasets? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running comprehensive performance tests..."
    
    # Run with normal test timeout 
    echo "• Performance test suite (with dataset creation)..."
    go test -v ./db -run "TestSearchPerformance" -timeout 10m
    
    echo ""
    echo "• Search benchmarks..."
    go test -v ./db -bench "BenchmarkSearchOperations" -benchtime=5s -timeout 5m
else
    echo "Skipping comprehensive tests."
fi

echo ""
echo "🔍 Quick Performance Validation"
echo "-------------------------------"
echo "Running fast performance tests for development..."

# Run fast performance tests
go test -v ./db -run "TestSearchPerformance" -short -timeout 2m

echo ""
echo "✅ Performance Testing Complete!"
echo ""
echo "📋 Summary"
echo "----------"
echo "• Basic search tests validate core functionality"
echo "• Search validation tests ensure input validation works"
echo "• Performance tests validate timing and memory usage"
echo "• Benchmarks measure specific operation performance"
echo ""
echo "🔧 Tips:"
echo "• Use -short flag for faster tests during development"
echo "• Use -timeout flag to prevent tests from hanging"
echo "• Check logs for performance warnings and memory usage"
echo "• Performance tests automatically adjust dataset size in -short mode"
echo ""
echo "📁 Test Files:"
echo "• db/search_test.go - Basic search functionality and validation"
echo "• db/search_performance_test.go - Comprehensive performance testing"
echo "• db/search_validator_test.go - Input validation testing"