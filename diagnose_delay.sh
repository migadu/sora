#!/bin/sh
# Diagnostic script to identify where IPv6 connection delay occurs
# Run this on the FreeBSD server

echo "=== FreeBSD IPv6 Connection Delay Diagnostics ==="
echo ""

# Test 1: Check if it's DNS reverse lookup
echo "Test 1: Checking for reverse DNS lookups..."
echo "Run: tcpdump -i any -n port 53 &"
echo "Then connect from client and watch for DNS queries"
echo ""

# Test 2: Check if it's in TCP handshake
echo "Test 2: Checking TCP handshake timing..."
echo "Run on server: tcpdump -i any -nn 'tcp port 995' -S"
echo "Then connect from client and measure time between SYN and SYN-ACK"
echo "Normal: < 1ms, Problem: ~60s delay"
echo ""

# Test 3: Check if it's in accept() call
echo "Test 3: Checking accept() call timing..."
echo "Add this to sora code in accept loop:"
echo '  startAccept := time.Now()'
echo '  conn, err := listener.Accept()'
echo '  logger.Info("Accept duration", "duration", time.Since(startAccept))'
echo ""

# Test 4: Check if it's in TLS handshake
echo "Test 4: Checking TLS handshake timing..."
echo "Add this to sora code after PerformHandshake():"
echo '  startHandshake := time.Now()'
echo '  err := tlsConn.PerformHandshake()'
echo '  logger.Info("TLS handshake duration", "duration", time.Since(startHandshake))'
echo ""

# Test 5: Check system settings
echo "Test 5: Checking FreeBSD IPv6 settings..."
sysctl net.inet6 | grep -E "(accept|dad|delay)"
echo ""

# Test 6: Check if specific to dual-stack
echo "Test 6: Current listen sockets..."
sockstat -46l | grep -E ':(995|993|143|110)'
echo ""

# Test 7: Check accept filters
echo "Test 7: Checking accept filters..."
sysctl net.inet.tcp.accf
echo ""

echo "=== Most Likely Causes ==="
echo "1. If delay is in TCP handshake (tcpdump shows SYN→SYN-ACK delay): Firewall/routing issue"
echo "2. If delay is in accept() call: Socket accept filter or kernel issue"
echo "3. If delay is in TLS handshake: Certificate/crypto issue"
echo "4. If DNS queries appear during delay: Reverse DNS lookup"
echo ""
echo "Run these tests and report back:"
echo "  A) What does 'time openssl s_client -6 -connect [::1]:995' show?"
echo "  B) What does tcpdump show during the delay?"
echo "  C) What are your net.inet6 sysctl values?"
