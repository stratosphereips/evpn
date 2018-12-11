#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of evpn, the Emergency VPN manager for CivilSphere project
#
# :authors: Israel Leiva <israel.leiva@usach.cl>
#           see also AUTHORS file
#
# :copyright: (c) 2018, all entities within the AUTHORS file
#
# :license: This is Free Software. See LICENSE for license information.

import os
import sys
import sqlite3
import argparse

VERSION = "0.1"

def print_header():
    header = """
                     ______     __   __   ______   __   __    
                    /\  ___\   /\ \ / /  /\  == \ /\ "-.\ \   
                    \ \  __\   \ \  \'/   \ \  _-/ \ \ \-.  \  
                     \ \_____\  \ \__|    \ \_\    \ \_\ \"\_\ 
                      \/_____/   \/_/      \/_/     \/_/ \/_/ 
                                                     
                      Emergency VPN Manager {} - Accounts.
    """.format(VERSION)
    print ""
    print "@"*100
    print "@"*100
    print header
    print "@"*100
    print ""

def print_footer():
    print ""
    print "@"*100
    print "@"*100
    print ""

def main():

    parser = argparse.ArgumentParser(
        description="Tool to create the evpn SQLite database."
    )

    parser.add_argument(
        "-d", "--database", default="database.db", metavar="database.db",
        help="Create SQLite database.")

    parser.add_argument(
        "-o", "--overwrite", action="store_true",
        help="Overwrite existing database."
    )

    args = parser.parse_args()

    if not args.overwrite and os.path.isfile(args.database):
        print "Database file already exists! Use -o to overwrite."
    else:
        conn = sqlite3.connect(args.database)
        with conn:
            c = conn.cursor()
            c.execute("DROP TABLE IF EXISTS requests")
            c.execute(
                "CREATE TABLE requests(username TEXT, email_addr TEXT, "
                "command TEXT, start_date TEXT, expiration_date TEXT, status "
                " TEXT, ip_addr TEXT)"
            )
        print "Database {} created".format(os.path.abspath(args.database))

if __name__ == "__main__":
    print_header()
    main()
    print_footer
