#!/bin/sh
psql -c "drop database imap_db"
psql -c "create database imap_db"