#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import sqlite3
import argparse


def main():

    parser = argparse.ArgumentParser(
        description="Tool to create an SQLite database."
    )

    parser.add_argument("-f", "--filename", default="database.db",
                        metavar="database.db",
                        help="Create SQLite database.")

    parser.add_argument("-o", "--overwrite", action="store_true",
                        help="Overwrite existing database.")

    args = parser.parse_args()

    if not args.overwrite and os.path.isfile(args.filename):
        print "Database file already exists! Use -o to overwrite."
    else:
        conn = sqlite3.connect(args.filename)
        with conn:
            c = conn.cursor()
            c.execute("DROP TABLE IF EXISTS requests")
            c.execute(
                "CREATE TABLE requests(username TEXT, email_addr TEXT, "
                "command TEXT, start_date TEXT, expiration_date TEXT, status "
                " TEXT, ip_addr TEXT)"
            )
        print "Database {} created".format(os.path.abspath(args.filename))

if __name__ == "__main__":
    main()
