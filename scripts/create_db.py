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

    parser.add_argument('-c', '--create', default=None,
                        metavar='filename.db',
                        help='create sqlite database')

    args = parser.parse_args()

    if len(sys.argv) < 2:
        print "Missing arguments!"
    elif os.path.isfile(args.create):
        print "Database file already exists!"
    else:
        conn = sqlite3.connect(args.create)
        with conn:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE requests(email_addr TEXT, command TEXT, "
                "start_date TEXT, expiration_date TEXT, status TEXT, ip_addr "
                "TEXT)"
            )
        print "Database %s created" % os.path.abspath(args.create)

if __name__ == "__main__":
    main()
