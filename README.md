pam_multipass
=============

Allows users to login to unix services with multiple, service-specific
passwords.

* Passwords are hashed using bcrypt.
* Adding or revoking a password does not require root access.
* Requires no SQL database nor directory server.
* A lightweight PAM module in C and a CLI in Python.

What pam_multipass is not:

* Not vetted by any security experts.
* Not a password manager like [KeePass](http://keepass.info/).
* Not for people who prefer GUIs.
* Not tested on anything but GNU/Linux. (Shouldn't be hard to port).
* Not designed for large companies.

Usage and Rationale
-------------------

I'd also like to save passwords in some trusted applications like the
email client on my home PC and my phone.  If I lose my phone, I want
to be able to revoke its password without having to reconfigure my PC.

So pam_multipass let's you login to your unix account with multiple
static passwords:

    $ multipass gen phone
    home [all]: sake newsy unworded gobbled

    $ multipass list
    home [all]
    phone [all]

    $ su myself
    Password: sake newsy unworded gobbled

Which are individually revokable:

    $ multipass revoke phone
    $ multipass list
    home [all]

    $ su myself
    Password: sake newsy unworded gobbled
    su: incorrect password

For convenience it comes with a couple of basic password generators
but feel make up your own.

    $ multipass gen work -g pw --length 20
    work [all]: |IlFAa'f;:-~hDRj6$Ko

    $ multipass gen teapot -g ask
    New password: 
    Confirm:
    teapot [all]: (hidden)

I'd also like the password I saved on my phone to just work with email
and instant messaging, not with SSH.  Each password can be qualified
with a list of PAM services:

    $ multipass gen phone --services dovecot,jabber
    phone [dovecot,jabber]: knees roommate iced caused

I'd like to use a [YubiKey](http://www.yubico.com/yubikey) for
two-factor authentication in environments I don't trust.  But one-time
passwords don't mix well with protocols like IMAP where clients open
multiple connections.  I also don't want to have to use a OTP all the
time, just from some devices.

I consider my work PC semi-trusted.  I'd like to be able login to my
IMAP server once each morning with a two-factor password that's
usable for 8 hours:

    # TODO: yubikey support is not implemented yet
    $ multipass gen work --yubikey --ttl 8h

It's no doubt possible to do all of the above by cobbling together the
right collection of existing PAM modules.  But I wanted something easy
to use and that doesn't need LDAP or a database server.

Install
-------

### Manual compile

Ensure you have these dependencies installed:

* GCC
* GNU Make
* PAM C headers
* [JSON-C](http://oss.metaparadigm.com/json-c/)
* [py-bcrypt](http://www.mindrot.org/projects/py-bcrypt/)

On Debian/Ubuntu try:

    $ sudo apt-get install build-essential libpam-dev libjson-dev python-bcrypt

On Fedora try:

    $ sudo yum install gcc make pam-devel json-c-devel py-bcrypt

Build it:

    $ make

And install it.

    $ sudo make install

Then you'll need to configure PAM to use it.  This varies from distro
to distro, but generally you'll want to put this line in
`/etc/pam.d/password-auth` or `/etc/pam.d/common-auth`:

    auth            sufficient      pam_multipass.so

Contribution of a proper Autotools build script would be most welcome.

### DPKG (Ubuntu/Debian)

TODO

### RPM (Fedora/EL)

TODO

### Package scripts for other distros

Contributions welcome.

Files
-----

Hashes of your passwords will be stored in `~/.multipass/hashes.json`.
You can put a wordlist for the passphrase generator in
~/.multipass/words`.  It will use `/usr/share/dict/words`
otherwise.

License
-------

pam_multipass itself is under a 2-clause BSD style license.  See
[LICENSE.txt].

The C module includes parts of the public domain Openwall
[crypt_blowfish 1.2](http://www.openwall.com/crypt/) by Solar
Designer.  See [crypt_blowfish.c].

The Python CLI requires [py-bcrypt](https://code.google.com/p/py-bcrypt/)
Damien Miller's Python wrapper of Niels Provos's OpenBSD bcrypt.
