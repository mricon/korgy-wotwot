#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2015 by The Linux Foundation and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)

__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import anyjson
import requests
import sys

from io import open

# Provided by pgp.cs.uu.nl, generated from wotsap
WEBURL = 'http://pgp.cs.uu.nl/paths/%s/to/%s.json'


def goodname(name):
    name = name.replace('"', '')
    name = name.split('<')[0].replace('"', '').strip()
    name = name.split('(')[0].strip()
    return name


def dotnode(member, color):
    node = '"%s" [color=%s,label="{%s|{%s|rank:%s}}"]' % (
        member['key'], color, goodname(member['uid']),
        member['key'], member['rnk'])
    return node


def analyze(topkey, botkey, dotgraph):
    # Get json between two keys
    url = WEBURL % (topkey, botkey)
    r = requests.get(url)
    if r.status_code != 200:
        sys.stderr.write('Could not grab %s\n' % url)
        sys.exit(1)

    web = anyjson.deserialize(r.content.decode('utf-8'))

    if len(web['error']):
        sys.stderr.write('Could not get results from server:\n')
        sys.stderr.write('%s\n' % web['error'])
        sys.exit(1)

    if dotgraph is not None:
        fh = open(dotgraph, 'w', encoding='utf-8')
    else:
        fh = sys.stdout

    fh.write('digraph "Tracing paths between %s and %s" {\n'
             % (goodname(web['FROM']['uid']), goodname(web['TO']['uid']))
             + 'node [shape=record]\n')

    # top key is purple, bottom key is gray
    # we write them out after we write out lineages, so collect them in a dict
    nodes = {
        web['FROM']['key']: dotnode(web['FROM'], 'purple'),
        web['TO']['key']: dotnode(web['TO'], 'gray'),
        }

    for entry in web['xpaths']:
        lineage = [web['FROM']['key']]
        for member in entry:
            lineage.append(member['key'])
            if member['key'] not in nodes:
                nodes[member['key']] = dotnode(member, 'orange')
        lineage.append(web['TO']['key'])

        fh.write('"' + '" -> "'.join(lineage) + '"\n')

    fh.write('\n')

    for key in nodes:
        fh.write('%s\n' % nodes[key])

    fh.write('}\n')


if __name__ == '__main__':
    from optparse import OptionParser

    usage = '''usage: %prog topkey bottomkey
    Create a dot graph of signatures
    '''

    op = OptionParser(usage=usage, version='0.1')
    op.add_option('-v', '--verbose', dest='verbose', action='store_true',
                  default=False,
                  help='Be verbose and tell us what you are doing')
    op.add_option('-o', '--output', dest='dotgraph',
                  default=None,
                  help='Write the DOT graph into this file (default stdout)')

    opts, args = op.parse_args()

    if len(args) != 2:
        op.error('Please provide two keys to trace')

    analyze(args[0], args[1], opts.dotgraph)
