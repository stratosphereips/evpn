# csvpn
CivilSphere VPN manager. The goal of **csvpn** is to provide an automated way
of handling creation of *OpenVPN* accounts via email. The manager provides the
following main functionalities:

  * Retrieve new mails from an email account via IMAP4 protocol.
  * Create and revoke OpenVPN accounts.
  * Start and stop traffic capture of new accounts with tcpdump.
  * Send mails via SMTP protocol.
  * Store accounts information in a SQLite database.

**csvpn** is implemented in Python using the *Twisted* engine.

# Setup
In addition to twisted, **csvpn** uses packages to perform DKIM and email
addresses verification. Below are the steps to setup **csvpn** in a Debian
system considering the use of *virtualenv*:

```
$ sudo apt-get install gcc python2.7 python-dev virtualenv sqlite3
$ virtualvenv venv
$ source venv/bin/activate
$ (venv) pip install twisted pydkim pyopenssl dnspython validate_email
```

# Usage
**csvpn** runs using **twistd** as follows:

```
$ python create_db.py -c csvpn.db
$ twistd -y csvpn.tac --logfile csvpn.log --pidfile csvpn.pid
```

To stop it just kill it using its process ID stored in csvpn.pid. Once
**csvpn** is running you can send an email to the defined email address
with the keywords **vpn account** to request the creation of a new
OpenVPN account. Any other keyword would be considered a help request
about its usage, and the manager will reply with instructions.

# Configuration
**csvpn** is made up of three services. *Accounts*, *Fetchmail* and *Messages*
. Each service has its own configuration, described below.

## Accounts
This service is on charge of create/revoke accounts, and start/stop traffic
capture of such accounts. Its configuration parameters are:

**general**

    interval: time interval (in seconds) of the service's main loop.
    expiration_days: amount of days an account expires after its creation.
    max_account_requests: how many accounts could be associated to a single email address.

**path**

    client-configs: path where account configuration files (.ovpn) will be stored.
    client-ips: path where configuration files for account's static IP address will be stored.
    openvpn-ca: path for openvpn-ca scripts.
    pcaps: path where the pcaps for each account will be stored.

**tcpdump**

    args: tcpdump list of arguments, separated by commas. It must include as first argument the path to tcpdump binary. It must also include the -i,interface arguments. An example of a list of arguments could be: /usr/sbin/tcpdump,-i,tun0,-n,-v. The list must not include the -w or host options.



**network**

    range: range of IPs used by OpenVPN (e.g. 10.8.0.0).
    mask: network mask used by OpenVPN (e.g. 255.255.255.0).
    reserved_ips: List of reserved IPs that should not be considered for allocation (e.g. OpenVPN server 10.8.0.1), separated by a comma.

## Fetchmail
This service is on charge of retrieving new mails from an IMAP server. Its
configuration parameters are:

**general**

    interval: time interval (in seconds) of the service's main loop.

**credentials**

    host: IMAP host.
    port: IMAP port.
    username: email account username.
    password: email account password.
    mbox: Mailbox from where to fetch new emails (e.g. INBOX).

## Messages
This service is on charge of sending emails to accounts users and the
CivilSphere team. Its configuration parameters are:

**general**

    interval: time interval (in seconds) of the service's main loop.
    max_help_requests: how many help requests can be processed for a single email address.
    cs_emails: email addresses of CivilSphere team for receiving notifications.

**credentials**

    host: SMTP host.
    port: SMTP port.
    username: email account username.
    password: email account password.

**subject**

    Email subjects for different messages sent by the manager.

**body**

    Email body for different messages sent by the manager.

# Database
**csvpn** uses an SQLite database to store information about new accounts. We 
consider every new (valid) mail received as a request to create an OpenVPN
account or to receive help about its usage, depending on the body of the
message. The structure of the database is very simple, and it contains one
table *requests* with the following columns:

    username: Account identifier. 
    email_addr: Email address of the request.
    command: Command extracted from the request. It could be `account` or `help`.
    start_date: The date when the account was created. Format Y-m-d.
    expiration_date: The date when the account will expire.
    status: account's status.
    ip_addr: IP address allocated in OpenVPN for the account.

Usernames are built using the email address and current date. One email address can have multiple accounts.

# License

**csvpn** is Free Software. See LICENSE for more information.