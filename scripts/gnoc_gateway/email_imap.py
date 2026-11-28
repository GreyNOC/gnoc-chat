"""Email: poll a mailbox over IMAP, answer over SMTP. The slowest adapter, and the one with the weakest identity.

The From header is whatever the sender typed, so an allowlisted address alone would let anyone who knows it
drive gnoc. A message counts only when the receiving mail server vouches for it: the FIRST Authentication-Results
header from the server named in GNOC_EMAIL_AUTHSERV (your provider's, e.g. mx.google.com) must show dmarc=pass
for the From domain, or dkim=pass signed by that domain. Only the first counts because a sender can add headers of
its own further down; the receiving server's sits on top. The reply goes to the From address that passed, never
to a Reply-To (which the sender also chooses). The IMAP search is narrowed to owner addresses and then re-checked
exactly, because IMAP's FROM search is a substring match. Approvals: reply `yes <id>` or `no <id>`.
"""
import email
import email.policy
import imaplib
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid, parseaddr

from .core import Adapter, Inbound

LIMIT = 60000
_ADDR = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_QUOTE_START = re.compile(r"^(>|On .{0,200} wrote:\s*$|-{2,}\s*Original Message\s*-{2,}|From: .+)", re.I)


def split_quoted(body):
    """(his new text, the quoted history). Top-posted replies put the quote below a marker line."""
    lines = (body or "").replace("\r\n", "\n").split("\n")
    for i, ln in enumerate(lines):
        if _QUOTE_START.match(ln.strip()):
            return "\n".join(lines[:i]).strip(), "\n".join(lines[i:]).strip()
    return "\n".join(lines).strip(), ""


def _hostport(v, default):
    host, _, port = (v or "").rpartition(":")
    if host and port.isdigit():
        return host, int(port)
    return v, default


class Email(Adapter):
    name = "email"
    max_len = LIMIT
    can_edit = False
    buttons = False

    def __init__(self, user, password, imap_host, smtp_host, owners, authserv, poll=60.0, log=None,
                 imap_factory=None, smtp_factory=None):
        self.user, self.password = user, password
        self.imap_addr = _hostport(imap_host, 993)
        self.smtp_addr = _hostport(smtp_host, 465)
        self.owners = frozenset(o.lower() for o in owners)
        self.authserv = (authserv or "").strip().lower()
        if not self.authserv:
            raise ValueError("GNOC_EMAIL_AUTHSERV is required: whose Authentication-Results header to trust")
        self.poll = float(poll)
        self.log = log or (lambda *a: None)
        self.imap_factory = imap_factory
        self.smtp_factory = smtp_factory
        self.threads = {}         # address -> (subject, message id) of its last message, for the reply headers

    # ---- identity

    def authenticated(self, msg, addr):
        domain = addr.rsplit("@", 1)[-1].lower()
        end = r"(?=[\s;)]|$)"     # x.com must not match header.from=x.com.attacker.example
        for h in msg.get_all("Authentication-Results") or []:
            text = " ".join(str(h).split()).lower()
            sid = text.split(";", 1)[0].strip().split(" ")[0] if text else ""
            if sid != self.authserv:
                continue
            if re.search(r"\bdmarc=pass\b[^;]*\bheader\.from=" + re.escape(domain) + end, text):
                return True
            if re.search(r"\bdkim=pass\b[^;]*\bheader\.(?:d=|i=@)" + re.escape(domain) + end, text):
                return True
            return False          # the top header from our server decides; one further down may be forged
        return False

    def parse(self, raw):
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        addr = parseaddr(str(msg.get("From") or ""))[1].lower()
        if addr not in self.owners:
            return None
        if not self.authenticated(msg, addr):
            self.log(f"email: ignored a message claiming to be from {addr}: the mail server did not vouch for it")
            return None
        part = msg.get_body(preferencelist=("plain",))
        body = part.get_content() if part is not None else ""
        own, quoted = split_quoted(body)
        subject = " ".join(str(msg.get("Subject") or "").split())[:200]
        mid = str(msg.get("Message-ID") or "").strip()
        self.threads[addr] = (subject, mid)
        inb = Inbound("email", addr, addr, text=own, message_id=mid, private=True)
        if quoted:
            inb.untrusted.append(("quoted text", quoted))
        if any(p.get_content_disposition() == "attachment" for p in msg.walk()):
            inb.notes.append("an attachment was sent; gnoc does not open attachments sent over the gateway")
        return inb

    # ---- wire

    def _imap(self):
        if self.imap_factory is not None:
            return self.imap_factory()
        return imaplib.IMAP4_SSL(self.imap_addr[0], self.imap_addr[1], timeout=30,
                                 ssl_context=ssl.create_default_context())

    def _smtp(self):
        if self.smtp_factory is not None:
            return self.smtp_factory()
        host, port = self.smtp_addr
        if port == 587:
            s = smtplib.SMTP(host, port, timeout=30)
            s.starttls(context=ssl.create_default_context())
            return s
        return smtplib.SMTP_SSL(host, port, timeout=30, context=ssl.create_default_context())

    def poll_once(self, gw):
        m = self._imap()
        try:
            m.login(self.user, self.password)
            m.select("INBOX")
            for owner in sorted(self.owners):
                typ, data = m.search(None, "UNSEEN", "FROM", f'"{owner}"')
                if typ != "OK" or not data or not data[0]:
                    continue
                for num in data[0].split():
                    typ, got = m.fetch(num, "(BODY.PEEK[])")
                    # marked read first: a message that breaks the parser must not be fetched again every minute
                    m.store(num, "+FLAGS", "\\Seen")
                    raw = next((x[1] for x in (got or []) if isinstance(x, tuple) and len(x) > 1), None)
                    if typ == "OK" and isinstance(raw, (bytes, bytearray)):
                        inb = self.parse(bytes(raw))
                        if inb is not None:
                            gw.handle(inb)
        finally:
            try:
                m.logout()
            except Exception:  # noqa: BLE001
                pass

    def send(self, chat_id, text, reply_to=None):
        to = str(chat_id).lower()
        if to not in self.owners:      # belt and braces: the core only ever hands over an inbound's own address
            raise ValueError("email: refusing to send to an address that is not an owner")
        subject, mid = self.threads.get(to, ("", ""))
        msg = EmailMessage(policy=email.policy.SMTP)
        msg["From"], msg["To"] = self.user, to
        msg["Subject"] = (subject if subject.lower().startswith("re:") else f"Re: {subject}") if subject else "gnoc"
        if mid:
            msg["In-Reply-To"], msg["References"] = mid, mid
        msg["Message-ID"] = make_msgid(domain=self.user.rsplit("@", 1)[-1] if "@" in self.user else None)
        msg.set_content(text[:LIMIT])
        s = self._smtp()
        try:
            s.login(self.user, self.password)
            s.send_message(msg, from_addr=self.user, to_addrs=[to])
        finally:
            try:
                s.quit()
            except Exception:  # noqa: BLE001
                pass
        return str(msg["Message-ID"])

    def run(self, gw, stop):
        backoff = self.poll
        while not stop.is_set():
            try:
                self.poll_once(gw)
                backoff = self.poll
            except (imaplib.IMAP4.error, OSError, ssl.SSLError, smtplib.SMTPException) as e:
                self.log(f"email: {type(e).__name__}; retrying")
                backoff = min(backoff * 2, 900.0)
            stop.wait(backoff)


def from_conf(conf, log=None):
    from .config import ids
    from .core import Allowlist
    keys = ("GNOC_EMAIL_USER", "GNOC_EMAIL_PASS", "GNOC_EMAIL_IMAP_HOST", "GNOC_EMAIL_SMTP_HOST", "GNOC_EMAIL_AUTHSERV")
    problems = [f"{k} is not set" for k in keys if not conf(k)]
    owners = {o.lower() for o in ids(conf("GNOC_EMAIL_OWNERS"), _ADDR)}
    if not owners:
        problems.append("GNOC_EMAIL_OWNERS is empty: gnoc would answer nobody (your own address)")
    if problems:
        return None, None, problems
    try:
        ad = Email(conf("GNOC_EMAIL_USER"), conf("GNOC_EMAIL_PASS"), conf("GNOC_EMAIL_IMAP_HOST"),
                   conf("GNOC_EMAIL_SMTP_HOST"), owners, conf("GNOC_EMAIL_AUTHSERV"), log=log)
    except ValueError as e:
        return None, None, [str(e)]
    return ad, Allowlist(owners, ()), []
