# Cloud MailDir Sync

This program will download a mailbox from the cloud into a local maildir,
monitor the local maildir for changes, then upload those changes back to the
cloud.

It is intended to allow normal Linux MailDir based progams, such as mutt and
gnus, to work with modern cloud based email.

There is much similarity to mbsync, but this program does not use IMAP for
manipulating email on the server.

## Ideal Usage

Although other use cases are possible, CMS was designed to support a 'Inbox
Zero' kind of workflow where email is read on a Linux laptop/desktop. It
supports multiple readers, including using the native cloud readers
concurrently.

Although it will function, it has not been optimized for giant email boxes and
may not perform well.

For safety it operates only in an 'online mode' where the daemon must be
running. Any local changes made to the mailboxes when the daemon is stopped
are discarded. A '--offline' flag will keep changes to flags in the local
mailbox (but ignores removed maildir files). This is relatively safe but could
potentially loose flag changes done on the cloud side.

# Microsoft Office365 Cloud Mailbox

The motivating reason to create this program was to support email from
Office365 using modern OAUTH2 based authentication. Not only is the IMAP
service in Offic365 very poor, it currently does not support OAUTH2 and is
thus often blocked by IT departments. This often means there is no good way to
access email from a Linux systems.

CMS's Office365 interface uses the [Microsoft Graph
REST](https://developer.microsoft.com/en-us/graph) interface over HTTP to
access the mailbox. Internally this uses a multi-connection/multi-threaded
approach that provides much better performance than the usual Office365 IMAP
service.

There is limited support for push notifications for new email as the Graph
interface does not support any way for clients to get notifications. Instead
an old OWA REST interface is used to get notifications.

Unlike IMAP, CMS is able to set the 'replied' flag in a way that shows up with
the other Outlook based clients. CMS is also able to set the 'ImmutableId'
flag which causes the server to provide long term stable IDs for the same
message. This avoids more cases where the messages have to be re-downloaded to
again match them to local messages.

# Gmail Cloud Mailbox

While Gmail has fairly good IMAP support, and does support OAUTH2 to IMAP, the
REST interface is a bit more scalable and robust.

CMS uses the [Gmail API](https://developers.google.com/gmail/api/guides) to
access the mailbox. It can be pointed at any Label in GMail and uses this
history scheme to optimize updates.

There is no support for push notifications as the Gmail API only considers
using notification in server/server configurations, not server/client.

The IMAP 'Replied' flag is not supported. The Gmail API does not seem to
expose this feature.

# Configuration

A small configuration file, written in Python, is used to setup the mailboxes
to download.

For instance, to synchronize a local MailDir from an Office 365 mail box use
the following `cms.cfg`:

```Python
MailDir("~/mail/INBOX")
Office365("inbox", Office365_Account(user="user@domain.com"))
```

and in case your work configuration requires you to use your specific tenant to
register `cloud_mdir_sync`

```Python
MailDir("~/mail/INBOX")
Office365("inbox", Office365_Account(user="user@domain.com", tenant="<MSFT tenant id>", client_id="<MSFT app client id>"))
```

or with Gmail:

```Python
MailDir("~/mail/INBOX")
GMail("INBOX", GMail_Account(user="user@domain.com"))
```

## Run from git

CMS requires a fair number of Python modules from PyPI that are not commonly
available from distributions. It is thus recommended it run it from a Python
virtual environment. The included 'cloud-mdir-sync' script will automatically
create the required virtual environment with the needed packages downloaded
with pip and then run the program from within it.

## Client side filtering

By default CMS supports only a single local MailDir. All cloud mailbox are
synchronized into it.

With client side filtering multiple local MailDirs can be used and messages
can be routed into them.

Here is an example of how to download from two cloud accounts into two
MailDirs:

```python
gmail_md = MailDir("~/mail/gmail")
gmail_cloud = GMail("INBOX", GMail_Account(user="user@domain.com"))

o365_md = MailDir("~/mail/o365")
o365_cloud = Office365("inbox", Office365_Account(user="user@domain.com"))

def direct_message(msg):
    if msg.mailbox is gmail_cloud:
        return gmail_md
    else:
        return o365_md
cfg.direct_message = direct_message
```

Filtering can also inspect message headers, this example will filter messages by
List-ID:

```python
def direct_message(msg):
    list_id = msg.get_header("List-ID")
    if list_id == "<foo-list>"
        return foo_md
    if list_id == "<bar-list>"
        return bar_md
    return default_md
```

All messages must be routed somewhere, they cannot be deleted through
directing.

# OAUTH2 Authentication

Most cloud providers are now using OAUTH2, and often also provide options to
disable simple password authentication. Both Microsoft and Google have
announced effective 'end of life' dates for password only 'basic
authentication'. This is done in the name of security as OAUTH is the
standards based way to support various MFA schemes. However, OAUTH requires an
interactive Web Browser to authenticate. This is challanging for a Linux
environment.

CMS implements this following [RFC 8252](https://tools.ietf.org/html/rfc8252)
which has become the common way for a command line application to operate. It
provides an internal web server which interacts with the browser to perform
the OAUTH protocol. When interactive authentication is required it
automatically launches a browser window to handle it. As a public application
CMS uses the new OAUTH 2.0 Proof Key for Code Exchange (PKCE) protocol with
the Authorization Code Grant to and does not need to keep secret information
to be secure.

The first time a user does this authentication they will be prompted to permit
the 'cloud-maildir-sync' application to access their mailbox, in the normal
way.

Browsing to http://localhost:8080/ will trigger authentication redirects until
all required OAUTH tokens are authorized. Once completed the browser window
can be closed.

## Interactive Authentication and Headless servers

The simplest approach is to port foward localhost:8080 along with the ssh
session and point a browser window at the forwarded port. Note, for OAUTH to
work the URL cannot be changed, it must still be http://localhost:8080/ after
forwarding.

At least Azure has a 'device authentication' approach that can be used for
command line applications, however it is not implemented in CMS.

## Secrecy of OAUTH tokens

The OAUTH exchange requests an 'offline_access' token which is a longer lived
token that can be refreshed. This token is sensitive information as it permits
access to the account until it expires.

CMS can cache this token on disk, in encrypted format, to avoid
re-authentication challenges. However that is only done if a local keyring is
avaiable. The Python [keyring](https://pypi.org/project/keyring/) module is
used to store the encryption secret for OAUTH token storage. For Linux desktop
appications this will automatically use gnome-keyring.

## OAUTH client_id's

OAUTH requires every client to register with the authentication server and get
a client_id for operation. The authorization server operator can excert quite
a lot of control over the process of granting a client_id. For instance Google
requires quite a long review process before they will grant a fully operational
client_id.

CMS comes included with default client_id's for GMail and Office365. However,
these IDs are hosted on various personal tenants, and have not necessarily
been made fully operational. While they are possibly good enough to get
started with this program, it is possible they will vanish some day, or hit
thier usage caps.

One might consult other, [more
popular](https://hg.mozilla.org/comm-central/diff/3f1827133f9d4d20979ba0c11b34005a27461194/mailnews/base/util/OAuth2Providers.jsm),
open source projects for OAuth client_ids.

# General Operation

CMS takes the approach that the cloud is the authoritative representation of
the mailbox.

Upone startup it forces the local maildirs to match the cloud configration,
downloading any missing messages and deleting messages not present in the
cloud.

Once completed it uses inotify to monitor changes in the MailDir and converts
them into REST operations for the cloud.

After changes to the remote mailbox are completed the local maildirs are again
forced to match the cloud and take on any changes made on the server.

## UID matching

All mailbox schemes generate some kind of unique ID for each message. This is
not related to the Message-ID headers of the email. Matching two emails
together without having the contents of both is troublesome.

Instead CMS uses the content hash of each message as the UID and maintains
caches for mapping each mailbox's unique UID scheme to the content hash. This
avoids having to re-download messages upon each startup.

To eliminate races, and for general sanity, a directory containing hard links
to each message, organized by content hash, is maintained automatically.

With this design the maildir files are never disturbed. Even if the cloud side
changes UIDs the content hash matching will keep the same filename for the
maildir after re-downloading the message.

## Offline Mode

The `--offline` command line argument will allow cloud-mdir-sync to trust the
local message flags. This mode is slightly dangerous as any dual-edit of
message flags (including deletion or undeletion!) will be resolved in favor of
the local state, not the cloud state. For message deletion to work with
offline mode the MUA must use the Trash flag.

# Mail User Agent Configuration

cloud-mdir-sync will work with any Maildir based MUA, however things will work
best if the MUA is configured to set the Trash flag on the message rather than
deleting them from the folder. Using the Trash flag allows cloud-mdir-sync to
keep track of changes in message flags during deletion.

For mutt use the following configuration:

```
set maildir_trash = yes
```

# Mail Delivery Agent Configuration

CMS includes a OAUTH broker than can export a SMTP access token to local SMTP
delivery agents. The [Outbound mail through SMTP](doc/smtp.md) page describes
this configuration.

# OAUTH only

CMS can also act as an OAUTH broker for other mail access programs, in this
mode it does not handle email. The [Inbound mail through IMAP](doc/imap.md)
page describes this configuration.

# Future Work/TODO
- Use delta queries on mailboxes with MS Graph. Delta queries allow
  downloading only changed message meta-data and will accelerate polling of
  large mailboxes.
- Implement an incremental JSON parser for GraphAPI.owa_get_notifications.
  Currently push notifications only work for a single mailbox as there is no
  way to determine which mailbox the notification was for unless the
  incremental JSON generated by the long-lived connection is parsed.
- Provide some web-app on 'http://localhost:8080/'. CMS launches a web browser
  using the Python webbrowser module to open a browser window on the URL,
  however this is only functional for desktop cases. Ideally just having a
  browser tab open to the URL would allow CMS to send some push notification
  to trigger authentication cycles, avoiding the need to open a new browser.
  This is probably essential for headless usage if token lifetimes are short.