#!/usr/bin/env python

import argparse
import sys

import app
from app.models import User
import getpass

def initialize_database():
    sys.stderr.write("Initializing the first user\n\n")

    field_names = {
        'email' : 'Email address',
        'first_name' : 'First name',
        'last_name' : 'Last name',
        'cb_username' : 'Mapped Carbon Black username'
    }

    field_order = ('email', 'first_name', 'last_name', 'cb_username')

    u = User()
    for field in field_order:
        sys.stderr.write(field_names[field] + ': ')
        sys.stderr.flush()
        response = sys.stdin.readline().strip()
        setattr(u, field, response)

    # capture password
    password_mismatch = True
    while password_mismatch:
        try:
            pass1 = getpass.getpass("Password: ")
            pass2 = getpass.getpass("Confirm : ")
            if pass1 == pass2:
                password_mismatch = False
            else:
                sys.stderr.write("Passwords don't match\n")
        except getpass.GetPassWarning:
            sys.exit(1)

    u.password = pass1

    app.create_base_data(u)


def main():
    parser = argparse.ArgumentParser(description="IdP development HTTP server and administration interface.")
    parser.add_argument('--init', action='store_true', dest='initialize',
                        help='Initialize the datastore. WARNING: this will delete ALL existing data', default=False)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose debugging messages & debugging. WARNING: this will give FULL ACCESS to your server through an open console for any errors', default=False)
    parser.add_argument('-p', '--port', action='store', type=int, dest='port_number',
                        help='Port number for IdP development server', default=7890)

    options = parser.parse_args()

    if options.initialize:
        sys.stderr.write('WARNING: this will delete ALL existing data!\n The user database and list of attached Carbon Black servers will be erased with this option.\n Type "yes" to continue and erase existing data or anything else to exit.\n')
        response = sys.stdin.readline()
        if response.strip() == 'yes':
            sys.stderr.write('Recreating database\n')
            initialize_database()
        else:
            sys.stderr.write('Database left untouched.\n')
        return 0

    app.app.run(host='0.0.0.0', port=options.port_number, debug=options.verbose)

if __name__ == '__main__':
    sys.exit(main())
