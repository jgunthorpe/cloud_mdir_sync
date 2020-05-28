# SPDX-License-Identifier: GPL-2.0+
import argparse
import base64
import re
import socket


def get_xoauth2_token(args):
    """Return the xoauth2 string. This is something like
        'user=foo^Aauth=Bearer bar^A^A'
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(args.cms_sock)
        sock.sendall(f"{args.proto} {args.user}".encode())
        sock.shutdown(socket.SHUT_WR)
        ret = sock.recv(16 * 1024).decode()
        if re.match("user=\\S+\1auth=\\S+ (\\S+)\1\1", ret) is None:
            raise ValueError(f"Invalid CMS server response {ret!r}")
        return ret


def test_smtp(args, xoauth2_token):
    """Initiate a testing SMTP connection to verify   """
    import smtplib
    conn = smtplib.SMTP(args.test_smtp, 587)
    conn.set_debuglevel(True)
    conn.ehlo()
    conn.starttls()
    conn.ehlo()
    conn.auth("xoauth2", lambda x: xoauth2_token, initial_response_ok=False)


def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--proto",
        default="SMTP",
        choices={"SMTP"},
        help="""Select the protocol to get a token for. The protocol will
        automatically select the correct OAUTH scope.""")
    parser.add_argument(
        "--user",
        required=True,
        help=
        """The cloud-mdir-sync user to access ie user@domain.com. This selects
        the cloud account from the CMS config file.""")
    parser.add_argument(
        "--cms_sock",
        required=True,
        help="The path to the cloud-mdir-sync CredentialServer UNIX socket")
    parser.add_argument(
        "--output",
        default="xoauth2",
        choices={"xoauth2", "xoauth2-b64", "token"},
        help="""The output format to present the token in. xoauth2-b64 is the
        actual final value to send on the wire in the XOAUTH2 protocol.
        xoauth2 is used if the caller will provide the base64 conversion.
        token returns the bare access_token""")

    parser.add_argument(
        "--test-smtp",
        metavar="SMTP_SERVER",
        help=
        """If specified attempt to connect and authenticate to the given SMTP
        sever. This can be used to test that the authentication method works
        properly on the server. Typical servers would be smtp.office365.com
        and smtp.gmail.com.""")
    args = parser.parse_args()

    xoauth2_token = get_xoauth2_token(args)
    if args.test_smtp:
        return test_smtp(args, xoauth2_token)

    if args.output == "xoauth2-b64":
        print(base64.b64encode(xoauth2_token.encode()).decode())
    elif args.output == "token":
        g = re.match("user=\\S+\1auth=\\S+ (\\S+)\1\1", xoauth2_token)
        print(g.group(1))
    else:
        print(xoauth2_token)


if __name__ == "__main__":
    main()
