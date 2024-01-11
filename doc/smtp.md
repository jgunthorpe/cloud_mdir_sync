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

## Configuration Test

CMS provides the *cms-auth* tool to get tokens out of the daemon. It has a
test mode which should be used to verify that the SMTP server is working correctly:

```sh
$ cms-oauth --user=user@domain.com --cms_sock=/var/run/user/XXX/cms.sock --test-smtp=smtp.office365.com
```

On success the last log line will report something like:

```
reply: retcode (235); Msg: b'2.7.0 Authentication successful'
```

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

# msmtp

msmtp is a small program that pretends to be sendmail and immeditately sends
the message to the configured server.  Newer versions have the ability to call
out to an external program to get an OAUTH token. An [example
configuration](example-msmtp.conf) is provided showing how to connect it to
CMS.

Support for gmail requires msmtp 1.8.4, and support for O365 requires msmtp
1.8.13.

# git send-email

There is currently no native support for XOAUTH2. When one of the above two
methods is used to setup a local sendmail, then use this .git_config:

```
[sendemail]
        smtpserver = /usr/bin/msmtp
        from = User Name <user@domain.com>
        envelopeSender = User Name <user@domain.com>
        assume8bitEncoding = UTF-8
        transferEncoding = auto
```

# Emacs smtpmail

Support for XOAUTH2 in emacs smtpmail was introduced in emacs-28.0.90. The elisp
below shows a simple configuration for supporting XOAUTH2 smtpmail
authentication with `cms-oauth`.

```elisp
(setq auth-sources '("~/.authinfo"      ; Default auth-source in Emacs (not needed)
                      "secrets:session" ; Use emacs auth-source to interface with libsecret
                      ))

(defun smtpmail-oauth-send-it ()
  (secrets-delete-item "session" "smtp")
  ;; smtpmail xoauth2 is sensitive to newlines
  ;; Use the --no_newline flag if choosing to use shell-command-to-string instead
  (let ((access-token (car (process-lines "cms-oauth"
                                          "--cms_sock=/var/run/user/XXX/cms.sock"
                                          "--proto=SMTP"
                                          "--user=user@domain.com"
                                          "--output=token"))))
    ;; Create item using libsecret
    (secrets-create-item "session" "smtp" access-token
                          :host "smtp.server.address"
                          :port "587"
                          ;; secrets.el only supports strings
                          ;;:smtp-auth "xoauth2" ;; Cannot use because of type mismatch with generic argument
                          :user "user@domain.com")
    )
  (smtpmail-send-it))

(setq message-send-mail-function 'smtpmail-oauth-send-it
      user-full-name "Full Name"
      user-mail-address "user@domain.com"
      smtpmail-default-smtp-server "smtp.server.address"
      smtpmail-auth-supported '(xoauth2)
      smtpmail-smtp-user "user@domain.com"
      smtpmail-smtp-service "587")
```
