pam_multipass
=============

Allows users to login to unix services with multiple, service-specific
passwords.

* Passwords are hashed using bcrypt.
* Adding or revoking a password does not require root access.
* One-time and time-limited passwords with a YubiKey in OTP mode.
* Requires no SQL database nor directory server.
* A lightweight PAM module in C and a CLI in Python.

What pam_multipass is not:

* Not vetted by any security experts.
* Not a password manager like [KeePass](http://keepass.info/).
* Not for people who prefer GUIs.
* Not tested on anything but Linux. (Might work though, try it).
* Not designed for large companies.

Rationale
---------

I'd like to use a [YubiKey](http://www.yubico.com/yubikey) for
two-factor authentication in environments I don't trust.  Trouble is
I'd also like to save a password in some trusted applications like the
email client on my home PC and on my phone.

If I lose my phone, I want to be able to revoke its password without
having to reconfigure my PC.  So pam_multipass gives your unix account
multiple individually revokable static passwords.

    $ multipass gen home
    $ multipass revoke home

I'd also like to limit the saved password has access to, just email,
while still having one memorized master password that gets me into
everything.  Each password can be qualified with a list of PAM
services it gives you access to.

    $ multipass gen phone --service dovecot,jabber

One-time passwords don't mix well by default with protocols like IMAP
where clients open multiple connections.  I consider my work PC
semi-trusted.  I'd like to be able login to my IMAP server once each
morning with a two-factor password that's valid for 8 hours.

    $ multipass gen work --yubikey --ttl 8h

While it's no doubt possible to do all this by cobbling together the
right collection of existing PAM modules, I find complex PAM setups
hard to understand.

License
-------

2-clause BSD.  See [LICENSE.txt].