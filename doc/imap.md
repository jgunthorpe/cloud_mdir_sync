# Inbound mail through IMAP

While CMS will not use IMAP directly, it can act as an OAUTH authentication
broker for other mail clients. In this mode CMS would be configured to only do
authentication and not handle mail.

## Authenticate only CMS Configuration

In this mode no mailboxes are defined, just accounts and the CredentialServer

```Python
account = Office365_Account(user="user@domain.com")
CredentialServer("/var/run/user/XXX/cms.sock",
                 accounts=[account],
                 protocols=["SMTP", "IMAP"])
```

CMS will still run as a daemon and it keeps track of the refresh token and
periodically updates the access tokens.

## Configuration Test

CMS provides the *cms-auth* tool to get tokens out of the daemon. It has a
test mode which should be used to verify that the IMAP server is working correctly:

```sh
$ cms-oauth --user=user@domain.com --cms_sock=/var/run/user/XXX/cms.sock --test-imap=outlook.office365.com
```

On success their should be a log  something like:

```
  40:51.37 < b'NDNI1 OK AUTHENTICATE completed.'
```

# mutt

Since Mutt 1.11 it has support for OAUTHBEARER authentication. This can be
used with GMail and CMS. The below fragment of the .mutt RC shows the configuration.

```
set imap_authenticators="oauthbearer"
set imap_oauth_refresh_command="cms-oauth --cms_sock=cms.sock --proto=IMAP --user user@domain --output=token"
set spoolfile="imaps://imap.gmail.com/INBOX"
```

As of mutt commit c7a872d1eeea ("Add basic XOAUTH2 support.") (possibly will
be in version 1.15) mutt can also do XOAUTH2 for use with Office365:

```
set imap_authenticators="xoauth2"
set imap_oauth_refresh_command="cms-oauth --cms_sock=cms.sock --proto=IMAP --user user@domain --output=token"
set spoolfile="imaps://outlook.office365.com/INBOX"
```
