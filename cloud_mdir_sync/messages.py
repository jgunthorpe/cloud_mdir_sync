# SPDX-License-Identifier: GPL-2.0+
import collections
import datetime
import email
import email.parser
import hashlib
import logging
import os
import pickle
import re
import stat
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING, Dict, Optional, Set, Tuple

import cryptography
import cryptography.exceptions
from cryptography.fernet import Fernet

from . import config, util

if TYPE_CHECKING:
    from . import mailbox

ContentHash_Type = str
CID_Type = tuple
CHMsgDict_Type = Dict[ContentHash_Type, "Message"]
MBoxDict_Type = Dict["mailbox.Mailbox", CHMsgDict_Type]
CHMsgMappingDict_Type = Dict[ContentHash_Type, Tuple[Optional["Message"],
                                                     Optional["Message"]]]

class Message(object):
    """A single message in the system"""
    content_hash: Optional[ContentHash_Type] = None
    received_time: Optional[datetime.datetime] = None
    flags = 0
    FLAG_REPLIED = 1 << 0
    FLAG_READ = 1 << 1
    FLAG_FLAGGED = 1 << 2
    FLAG_DELETED = 1 << 3
    ALL_FLAGS = FLAG_REPLIED | FLAG_READ | FLAG_FLAGGED | FLAG_DELETED
    fn: Optional[str] = None
    size: Optional[int]

    def __init__(self, mailbox, storage_id, email_id=None):
        assert storage_id
        self.mailbox = mailbox
        self.storage_id = storage_id
        self.email_id = email_id

    def cid(self):
        """The unique content ID of the message. This is scoped within the
        mailbox and is used to search for the content_hash"""
        return (self.mailbox.storage_kind, self.storage_id, self.email_id)

    def __getstate__(self):
        return {
            "content_hash": self.content_hash,
            "received_time": self.received_time,
            "flags": self.flags,
            "storage_id": self.storage_id,
            "email_id": self.email_id
        }

    def _read_header(self, hdr):
        msgdb = self.mailbox.msgdb
        if self.fn:
            fn = self.fn
        else:
            assert self.content_hash is not None
            fn = os.path.join(msgdb.hashes_dir, self.content_hash)
        with open(fn, "rb") as F:
            emsg = email.parser.BytesParser().parsebytes(F.read())
            # Hrm, I wonder if this is the right way to normalize a header?
            val = emsg.get(hdr)
            if val is None:
                return None
            return re.sub(r"\n[ \t]+", " ", val).strip()

    def fill_email_id(self):
        """Try to fill in the email_id from our caches or by reading the
        message itself"""
        if self.email_id is not None:
            # Check or cache the email_id provided by the Mailbox
            content_msg_header = self.mailbox.msgdb.content_msg_header
            oval = content_msg_header.get((self.content_hash, "message-id"))
            if oval is None:
                content_msg_header[(self.content_hash, "message-id")] = oval
            else:
                assert oval == self.email_id
            return
        self.email_id = self.get_header("message-id")

    def get_header(self, hdr):
        """Return a email header from a message"""
        hdr = hdr.lower()
        content_msg_header = self.mailbox.msgdb.content_msg_header
        val = content_msg_header.get((self.content_hash, hdr), False)
        if val is not False:
            return val
        val = self._read_header(hdr)
        content_msg_header[(self.content_hash, hdr)] = val
        return val

class MessageDB(object):
    """The persistent state associated with the message database. This holds:
        - A directory of content_hash files for mailbox content
        - A set of files of pickles storing the mapping of CID to content_hash
    """
    content_hashes: Dict[CID_Type, ContentHash_Type]
    content_hashes_cloud: Dict[CID_Type, ContentHash_Type]
    content_msg_header: Dict[Tuple[ContentHash_Type, str], str]
    alt_file_hashes: Dict[ContentHash_Type, set]
    inode_hashes: Dict[tuple, ContentHash_Type]
    file_hashes: Set[str]
    authenticators_to_save: Set[str]
    authenticators: Dict[str, Tuple[int, bytes]]

    @util.log_progress(
        "Loading cached state",
        lambda self:
        f", {len(self.file_hashes)} msgs, {len(self.content_hashes)} cached ids",
        level=logging.DEBUG)
    def __init__(self, cfg: config.Config):
        self.cfg = cfg
        self.content_hashes = {}  # [cid] = content_hash
        self.content_msg_header = {}  # [hash,msg_header] = value
        self.file_hashes = set()
        self.alt_file_hashes = collections.defaultdict(
            set)  # [hash] = set(fns)
        self.inode_hashes = {}  # [inode] = content_hash
        self.authenticators_to_save = set()
        self.authenticators = {}  # [did] = (serial, blob)

        self.state_dir = os.path.expanduser(cfg.message_db_dir)
        self.hashes_dir = os.path.join(self.state_dir, "hashes")
        os.makedirs(self.hashes_dir, exist_ok=True)
        self._load_file_hashes(self.hashes_dir)
        self._load_content_hashes()

    def close(self):
        try:
            self._save_content_hashes()
        except IOError:
            pass

    def _save_content_hashes(self):
        """Store the current content_hash dictionary in a file named after its
        content. This allows us to be safe against FS problems on loading"""
        data = pickle.dumps({
            "content_hashes":
            self.content_hashes,
            "authenticators_enc":
            self._encrypt_authenticators(),
        })
        m = hashlib.sha1()
        m.update(data)
        with open(os.path.join(self.state_dir, "ch-" + m.hexdigest()),
                  "xb") as F:
            F.write(data)

    def _load_content_hash_fn(self, fn, dfn):
        with open(dfn, "rb") as F:
            data = F.read()
            st = os.fstat(F.fileno())

        m = hashlib.sha1()
        m.update(data)
        if fn != "ch-" + m.hexdigest():
            os.unlink(dfn)
            return ({}, None)
        return (pickle.loads(data), st[stat.ST_CTIME])

    def _load_content_hashes(self):
        """Load every available content hash file and union their content."""
        states = []
        res: Dict[CID_Type, ContentHash_Type] = {}
        blacklist = set()
        for fn in os.listdir(self.state_dir):
            if not fn.startswith("ch-"):
                continue

            dfn = os.path.join(self.state_dir, fn)
            try:
                state, ctime = self._load_content_hash_fn(fn, dfn)
            except (IOError, pickle.PickleError):
                os.unlink(dfn)

            if ctime is not None:
                states.append((ctime, dfn))
            for k, v in state.get("content_hashes", state).items():
                if res.get(k, v) != v:
                    blacklist.add(k)
                res[k] = v
            self._load_authenticators(state.get("authenticators_enc"))

        # Keep the 5 latest state files
        states.sort(reverse=True)
        for I in states[5:]:
            os.unlink(I[1])

        for k in blacklist:
            del res[k]
        for cid, ch in res.items():
            self.content_msg_header[ch,"message-id"] = cid[2]
        self.content_hashes = res

        # Build a mapping with only the mailbox ID, no message_id
        no_msg_id: Dict[CID_Type, ContentHash_Type] = {}
        for cid,ch in res.items():
            ncid = (cid[0], cid[1], None)
            if no_msg_id.get(ncid, ch) != ch:
                del no_msg_id[ncid]
            else:
                no_msg_id[ncid] = ch
        self.content_hashes_cloud = no_msg_id

    def _sha1_fn(self, fn):
        sha1 = hashlib.sha1()  # Create a new SHA-1 hash object
        with open(fn, 'rb') as file:
            # Read the file in chunks to avoid loading large files into memory
            while chunk := file.read(8192):
                sha1.update(chunk)
        return sha1.hexdigest()  # Return the hex digest of the file

    def _load_file_hashes(self, hashes_dir):
        """All files in a directory into the content_hash cache. This figures out what
        stuff we have already downloaded and is crash safe as we rehash every
        file. Accidental duplicates are pruned along the way."""
        hashes = set()
        # Since we don't use sync the files can be corrupted, check them.
        dirl = [fn for fn in os.listdir(hashes_dir) if not fn.startswith(".")]
        while dirl:
            chunk = dirl[:500]
            del dirl[:500]
            sha1 = subprocess.check_output(["sha1sum"] + chunk,
                                           cwd=hashes_dir).decode()
            lines = sha1.splitlines()
            assert(len(chunk) == len(lines))
            for fn,ln in zip(chunk,lines):
                ch, _, check_fn = ln.partition('  ')
                assert(check_fn == fn)

                ffn = os.path.join(hashes_dir, fn)
                if fn == ch:
                    hashes.add(ch)
                    st = os.stat(ffn)
                    inode = (st.st_ino, st.st_size, st.st_mtime, st.st_ctime)
                    self.inode_hashes[inode] = ch
                else:
                    os.unlink(ffn)
        self.file_hashes.update(hashes)

    def have_content(self, msg: Message):
        """True if we have the message contents for msg locally, based on the
        storage_id and email_id"""
        if msg.content_hash is None:
            msg.content_hash = self.content_hashes.get(msg.cid())

        # If we have this in some other file, link it back to the hashes dir
        if (msg.content_hash is not None
                and msg.content_hash not in self.file_hashes):
            for fn in self.alt_file_hashes.get(msg.content_hash, []):
                hfn = os.path.join(self.hashes_dir, msg.content_hash)
                try:
                    os.link(fn, hfn)
                    self.file_hashes.add(msg.content_hash)
                except FileNotFoundError:
                    continue

        return (msg.content_hash is not None
                and msg.content_hash in self.file_hashes)

    def msg_from_file(self, msg, fn):
        """Setup msg from a local file, ie in a Maildir. This also records that we
        have this message in the DB"""
        st = os.stat(fn)
        inode = (st.st_ino, st.st_size, st.st_mtime, st.st_ctime)
        msg.content_hash = self.inode_hashes.get(inode)
        if msg.content_hash is None:
            msg.content_hash = self._sha1_fn(fn)
            self.inode_hashes[inode] = msg.content_hash

        msg.fn = fn
        self.alt_file_hashes[msg.content_hash].add(fn)
        msg.fill_email_id()

    def update_inode_cache(self, msg):
        """After the message has been hardlinked or the times adjusted,
        the inode cache needs to be updated with the new times"""
        st = os.stat(msg.fn)
        inode = (st.st_ino, st.st_size, st.st_mtime, st.st_ctime)
        self.inode_hashes[inode] = msg.content_hash

    def write_content(self, content_hash, dest_fn):
        """Make the filename dest_fn contain content_hash's content"""
        assert content_hash in self.file_hashes
        os.link(os.path.join(self.hashes_dir, content_hash), dest_fn)

    def get_temp(self):
        """Return a file for later use by store_hashed_file"""
        return tempfile.NamedTemporaryFile(dir=self.hashes_dir)

    def store_hashed_msg(self, msg : Message, tmpf):
        """Retain the content tmpf in the hashed file database"""
        tmpf.flush()
        ch = self._sha1_fn(tmpf.name)
        fn = os.path.join(self.hashes_dir, ch)
        if ch not in self.file_hashes:
            # Adopt the tmpfile into the hashes storage
            os.link(tmpf.name, fn)
            self.file_hashes.add(ch)
            st = os.stat(fn)
            inode = (st.st_ino, st.st_size, st.st_mtime, st.st_ctime)
            self.inode_hashes[inode] = ch

        msg.content_hash = ch
        assert msg.fn is None
        msg.fill_email_id()

        cid = msg.cid()
        self.content_hashes[msg.cid()] = ch
        ncid = (cid[0], cid[1], None)
        self.content_hashes_cloud[ncid] = ch

        assert self.have_content(msg)
        return ch

    def cleanup_msgs(self, msgs_by_local: MBoxDict_Type):
        """Clean our various caches to only have current messages"""
        all_chs: Set[ContentHash_Type] = set()
        for msgdict in msgs_by_local.values():
            all_chs.update(msgdict.keys())
        for ch in self.file_hashes - all_chs:
            try:
                os.unlink(os.path.join(self.hashes_dir, ch))
            except FileNotFoundError:
                pass
            self.file_hashes.remove(ch)

        # Remove obsolete items in the inode cache
        to_del = []
        for ino, ch in self.inode_hashes.items():
            if ch not in all_chs:
                to_del.append(ino)
        for ino in to_del:
            del self.inode_hashes[ino]

    def _encrypt_authenticators(self):
        crypto = Fernet(self.cfg.storage_key)
        return crypto.encrypt(
            pickle.dumps({
                k: v
                for k, v in self.authenticators.items()
                if k in self.authenticators_to_save
            }))

    def _load_authenticators(self, data):
        if data is None:
            return
        crypto = Fernet(self.cfg.storage_key)
        try:
            plain_data = crypto.decrypt(data)
        except (cryptography.exceptions.InvalidSignature,
                cryptography.fernet.InvalidToken):
            return
        for k, v in pickle.loads(plain_data).items():
            if v[0] > self.authenticators.get(k, (0, ))[0]:
                self.authenticators[k] = v

    def get_authenticator(self, domain_id):
        """Return the stored authenticator data for the domain_id"""
        auth = self.authenticators.get(domain_id)
        if auth is None:
            return None
        return auth[1]

    def set_authenticator(self, domain_id, value):
        """Store authenticator data for the domain_id. The data will persist
        across reloads of the message db. Usually this will be the OAUTH
        refresh token."""
        self.authenticators_to_save.add(domain_id)
        serial, cur = self.authenticators.get(domain_id, (0, None))
        if cur == value:
            return
        self.authenticators[domain_id] = (serial + 1, value)
