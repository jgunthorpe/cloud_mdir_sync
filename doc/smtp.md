# Outbound mail through SMTP

The cloud services now all support OAUTH2 as an authentication method for
SMTP, and CMS provides an internal broker service to acquire and expose the
OAUTH access token needed for SMTP.

This allows the use of several normal SMTP tools without having to revert
to BASIC authentication.

## CMS Configuration

CMS uses a UNIX domain socket to expose the access token. CMS must be running
to maintain a fresh token.

This feature is enabled in the configuration file:

```Python
account = Office365_Account(user="user@domain.com")
Office365("inbox", account)
CredentialServer("/var/run/user/XXX/cms.sock",
                 accounts=[account])
```

Upon restart CMS will acquire and maintain a OAUTH token with the SMTP scope
for the specified accounts, and serve token requests on the specified path.

# exim 4

Exim is a long standing UNIX mail system that is fully featured. exim's flexible
authentication can support the use of OAUTH tokens:

```
begin authenticators

xoauth2_smart:
  driver = plaintext
  client_condition = ${if !eq{$tls_out_cipher}{}}
  public_name = XOAUTH2
  client_ignore_invalid_base64 = true
  client_send = : ${readsocket{/home/XX/mail/.cms/exim/cms.sock}{SMTP user@domain}}
```

Since exim runs as a system daemon, permissions must be set to allow access to
the socket:

```sh
cd /home/XX/mail/.cms
mkdir exim
chmod 0750 exim
sudo chgrp Debian-exim cms
```

And the CMS configuration must specify a umask:

```Python
CredentialServer("/home/XX/mail/.cms/exim/cms.sock",
                 accounts=[account],
				 umask=0o666)
```

A fully functional [exim4.conf](example-exim4.conf) is provided. This minimal,
relay only config can replace the entire configuration from the distro, after
making the adjustments noted. In this mode /usr/bin/sendmail will be fully
functional for outbound mail and if multiple accounts are required, it will
automatically choose the account to send mail through based on the Envelope
From header.
