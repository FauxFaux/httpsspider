#!/usr/bin/python3

import sys

# sagi python3-dnspython
import dns.resolver
import psycopg2

def main():
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = ['127.0.0.1']
    res.port = 3007

    with psycopg2.connect('') as conn:
        with conn.cursor() as cur:
            for name in sys.argv[1:]:
                try:
                    for addr in (x.address for x in res.query(name, 'A')):
                        cur.execute('INSERT INTO lookups (name, addr) VALUES (%s, %s)',
                                (name, addr))
                except Exception as e:
                    print('name failed: {}: {}'.format(name, e))
        conn.commit()
    conn.close()


if __name__ == '__main__':
    main()

