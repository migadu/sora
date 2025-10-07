#!/usr/bin/perl
#
# sieve-auth-command.pl
# ---------------------
#
# Generates ManageSieve AUTHENTICATE command for manually testing the protocol 
# using telnet or gnutls-cli (TLS)
#
# Usage:
#   sieve-auth-command.pl <username> <password>
#
# Prints the AUTHENTICATE "PLAIN" "<encoded>" command on standard out. 
#
# --
# Stephan Bosch, stephan@rename-it.nl
#
    
use MIME::Base64;
    
use strict;
    
my $username = shift;
my $password = shift;
    
my $userpass = "\x00".$username."\x00".$password."";
my $encode=encode_base64($userpass);
    
$encode =~ s/^\s+//;
$encode =~ s/\s+$//;
    
print "AUTHENTICATE \"PLAIN\" \"$encode\"\r\n";

