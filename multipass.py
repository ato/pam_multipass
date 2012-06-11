#!/usr/bin/env python
#
# CLI config tool for pam_multipass
#
# Author: Alex Osborne 2012
# License: 2-clause BSD.  See LICENSE.txt for details.
#
import sys, os, argparse, bcrypt, json, gzip, random, getpass

def mp_home():
    path = (os.environ.get('MULTIPASS_HOME') or
            os.path.join(os.environ['HOME'], '.multipass'))
    if not os.path.isdir(path):
        os.mkdir(path, 0o700)
    if (os.stat(path).st_mode & 0o777) != 0o700:
        sys.stderr.write('Bad permissions.  Must be mode 0700: ' + path)
        sys.exit(1)
    return path

def wordlist():
    search = [os.environ.get('MULTIPASS_WORDS'),
              os.path.join(mp_home(), 'words.gz'),
              os.path.join(mp_home(), 'words'),
              '/usr/share/dict/words']
    found = [path for path in search if path and os.path.exists(path)]
    if not found:
        sys.stderr.write('multipath: no wordlist found for passphrase generator.\n'
                         'Set MULTIPASS_WORDS, make a ~/.multipass/words or use "-g ask".\n')
        sys.exit(1)
    path = found[0]
    f = gzip.open(path) if path.endswith('.gz') else open(path)
    with f:
        words = []
        for line in f:
            line = line.strip()
            if line[0] == '#': continue
            words.append(line)
        return words

def ppgen(length=4):
    "Passphrase generator."
    r = random.SystemRandom()
    wl = wordlist()
    words = []
    for i in range(length):
        words.append(wl[r.randint(0, len(wl))])
    return ' '.join(words)

def pwgen(length=12):
    "Password generator."
    r = random.SystemRandom()
    s = ''
    for i in range(length):
        s += chr(r.randint(0x21, 0x7e))
    return s

def askgen(length=None):
    "Prompt for a password."
    while True:
        pw = getpass.getpass("New password: ")
        pwc = getpass.getpass("Confirm: ")
        if pw == pwc: break
        print "Passwords do not match, try again."
    return pw

GENERATORS = {"pw": pwgen, "pp": ppgen, "ask": askgen}

def hashes_file():
    return os.path.join(mp_home(), 'hashes.json')

def read_hashes():
    try:
        with open(hashes_file()) as f:
            return json.load(f)
    except IOError:
        return {}

def write_hashes(hashes):
    tmp = hashes_file() + '.new'
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as f:
        json.dump(hashes, f)
    os.rename(tmp, hashes_file())

def fmt_services(services):
    return '[%s]' % (','.join(services),)

def gen(args):
    name = args.name
    services = args.services.split(',')
    length = args.length
    genfunc = GENERATORS[args.generator]
    pw = genfunc(length) if length else genfunc()
    if not pw:
        print 'No password given, aborting.'
        return
    hashes = read_hashes()
    hashes[name] = {'hash': bcrypt.hashpw(pw, bcrypt.gensalt(8)),
                    'services': services}
    if args.generator == 'ask': pw = '(hidden)'
    print name, fmt_services(services) + ":", pw
    write_hashes(hashes)

def revoke(args):
    hashes = read_hashes()
    del hashes[args.name]
    write_hashes(hashes)

def listpw(args):
    hashes = read_hashes()
    for name, rec in sorted(hashes.iteritems()):
        print '%12s %s' % (name, fmt_services(rec['services']))

def main():
    parser = argparse.ArgumentParser(description='Configure multiple PAM passwords.')
    subparsers = parser.add_subparsers(help='sub-command help')
    # gen
    parser_gen = subparsers.add_parser('gen', help='generate a new password')
    parser_gen.add_argument('name',
                            help='nickname of password to revoke')
    parser_gen.add_argument('-s', '--services', dest='services', default='all',
                            help='Comma-separated list of PAM services this '
                            'password should give access to (default: all)')
    parser_gen.add_argument('-g', '--generator', dest='generator', default='pp',
                            choices=GENERATORS,
                            help='Password generator to use (default: pp)')
    parser_gen.add_argument('-l', '--length', dest='length', type=int,
                            help='Generated password length (defaults: pp=4, pw=12)')
    parser_gen.set_defaults(func=gen)

    # revoke
    parser_revoke = subparsers.add_parser('revoke', help='revoke an existing password')
    parser_revoke.add_argument('name',
                               help='a nickname for this password')
    parser_revoke.set_defaults(func=revoke)

    # list
    parser_revoke = subparsers.add_parser('list', help='list configured hashes')
    parser_revoke.set_defaults(func=listpw)

    args = parser.parse_args()

    if args.func:
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__': main()
