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

import sqlite3
import argparse

from datetime import datetime, timedelta

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
	"""
	Script for managing accounts.
	See argparse usage for more details.
	"""
	parser = argparse.ArgumentParser(
		description="Tool for managing CSVPN accounts."
	)

	parser.add_argument(
		"-d", "--database", type=str, metavar="database.db",
		help="The SQLite database."
	)

	parser.add_argument(
		"-l", "--list", action="store_true", help="List existing accounts."
	)

	parser.add_argument(
		"-n", "--new", type=str, metavar="foo@bar.baz",
		help="Email address for the new account."
	)

	parser.add_argument(
		"-s", "--set", type=str, metavar="user-01011970",
		help="Set value for existing account."
	)

	parser.add_argument(
		"--expiration-date", type=str, metavar="01-01-1970",
		help="Expiration date of the account."
	)

	parser.add_argument(
		"-e", "--expire", type=str, metavar="user-01011970", 
		help="Expire existing account."
	)

	parser.add_argument(
		"-r", "--remove", type=str, metavar="user-01011970",
		help="Remove existing account."
	)

	args = parser.parse_args()

	if args.database:
		con = sqlite3.connect(args.database)
	else:
		print " Missing database. Use -d or --database."

	if args.new:
		# Generate username based on email prefix and current date.
		username, domain = args.new.split('@')
		now_str = datetime.now().strftime("%Y%m%d%H%M%S")
		username = "{}-{}".format(username, now_str)
		print " Adding new account with username {} and email address {}"\
			.format(username, args.new)

		if args.expiration_date:
			expiration_date = args.expiration_date
		else:
			expiration_date = ''

		query = "INSERT INTO requests VALUES('{}', '{}', 'account', '', '{}'"\
			", 'ONHOLD', '')"\
			.format(username, args.new, expiration_date)

		with con:
			cur = con.cursor()
			cur.execute(query)

	elif args.expire:
		print " Expiring account with username {}".format(args.expire)
		# Set expiration to now - 1 day. CSVPN will do the expiration process.
		now_str = datetime.now().strftime("%Y-%m-%d")
		now_date = datetime.strptime(now_str, "%Y-%m-%d")
		exp_date = now_date - timedelta(days=1)
		exp_date_str = exp_date.strftime("%Y-%m-%d")
		query = "UPDATE requests SET expiration_date='{}' WHERE "\
			"username='{}'"\
			.format(exp_date_str, args.expire)
		with con:
			cur = con.cursor()
			cur.execute(query)

	elif args.remove:
		print " Removing account with username {}".format(args.remove)
		query = "DELETE FROM requests WHERE username='{}'".format(args.remove)

		with con:
			cur = con.cursor()
			cur.execute(query)

	elif args.set:
		if args.expiration_date:
			print " Setting expiration_date for {} to {}".format(
				args.expiration_date, args.set
			)
			query = "UPDATE requests set expiration_date = '{}' WHERE "\
			"username='{}'"\
			.format(args.expiration_date, args.set)

			with con:
				cur = con.cursor()
				cur.execute(query)

	elif args.list:
		query = "SELECT * FROM requests WHERE command='account'"
		with con:
			cur = con.cursor()
			cur.execute(query)
			rows = cur.fetchall()
			# show it nice
			print "\nNumber of accounts: %s\n" % len(rows)
			cns = [cn[0] for cn in cur.description]

			print "{:50} {:40} {:15} {:20} {:15} {:2}".format(
				cns[0], cns[1], cns[3], cns[4], cns[6], cns[5]
			)
			for row in rows:
				print "{:50} {:40} {:15} {:20} {:15} {:2}".format(
					row[0], row[1], row[3], row[4], row[6], row[5]
				)
	else:
		print " Missing parameters. Use -h or --help for help."

if __name__ == "__main__":
	print_header()
	main()
	print_footer()
