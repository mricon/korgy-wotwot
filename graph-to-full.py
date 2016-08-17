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

from io import open

import anyjson
import requests
import sys

# Provided by pgp.cs.uu.nl, generated from wotsap
WEBURL = 'http://pgp.cs.uu.nl/paths/%s/to/%s.json'


def loadtrust(trustfile):
    trustdb = {}
    fh = open(trustfile, 'r', encoding='utf-8')
    while True:
        line = fh.readline()
        if not line:
            break
        if line[0] == '#':
            continue
        line = line.rstrip('\n')
        line = line.rstrip(':')
        fpr, level = line.split(':')
        trustdb[fpr[-8:]] = int(level)
    return trustdb


def goodname(name):
    name = name.replace('"', '')
    name = name.split('<')[0].replace('"', '').strip()
    name = name.split('(')[0].strip()
    return name


def analyze(key, trustfile, dotgraph):
    trustdb = loadtrust(trustfile)
    # Get all the full/ultimate trusted keys (anchors)
    seen_members = {}
    lineages = []

    for anchorkey in trustdb:
        if trustdb[anchorkey] <= 4:
            continue

        # Get json to the anchor
        url = WEBURL % (anchorkey, key)
        r = requests.get(url)
        if r.status_code != 200:
            sys.stderr.write('Could not grab %s\n' % url)
            sys.exit(1)

        web = anyjson.deserialize(r.content.decode('utf-8'))

        if len(web['error']):
            sys.stderr.write('Could not get results from server:\n')
            sys.stderr.write('%s\n' % web['error'])
            sys.exit(1)

        if web['FROM']['key'] not in seen_members:
            seen_members[web['FROM']['key']] = goodname(web['FROM']['uid'])

        if web['TO']['key'] not in seen_members:
            seen_members[web['TO']['key']] = goodname(web['TO']['uid'])

        # Basically, we look at any paths that consist of marginals
        # that we take from our exported ownertrust.out
        for entry in web['xpaths']:
            if len(entry) > 4:
                # Too long!
                continue

            lineage = []
            ignore_lineage = False

            for member in entry:

                if member['key'] not in trustdb.keys():
                    # We can ignore this lineage
                    ignore_lineage = True
                    break

                if trustdb[member['key']] != 4:
                    # We ignore anything that's not a marginal
                    ignore_lineage = True
                    break

                if member['key'] not in seen_members:
                    seen_members[member['key']] = goodname(member['uid'])

                lineage.append(member['key'])

            if not ignore_lineage and len(lineage):
                # Have we traced this direct signor to an anchor already?
                for seen_lineage in lineages:
                    if seen_lineage[-2] == lineage[-1]:
                        ignore_lineage = True

                if not ignore_lineage:
                    lineages.append([web['FROM']['key']]
                                    + lineage + [web['TO']['key']])

    # cull seen_members to only include people actually in lineages
    print_members = {}
    for lineage in lineages:
        for memberkey in lineage:
            if memberkey not in print_members:
                print_members[memberkey] = seen_members[memberkey]

    # Now generate the WOT output
    if dotgraph is not None:
        fh = open(dotgraph, 'w', encoding='utf-8')
    else:
        fh = sys.stdout

    fh.write('digraph "Tracing results" {\n'
             + 'node [shape=record]\n'
             + 'subgraph cluster0 {\n'
             + '    color=white\n')

    # Write out all anchors first
    for memberkey in print_members:
        if memberkey in trustdb and trustdb[memberkey] > 4:
            fh.write('    "%s" [color=red,label="{%s|{%s|t:full}}"]\n'
                     % (memberkey, seen_members[memberkey], memberkey))

    fh.write('}\n\n')

    for lineage in lineages:
        fh.write('"' + '" -> "'.join(lineage) + '"\n')

    fh.write('\n')

    for memberkey in print_members:
        if memberkey in trustdb and trustdb[memberkey] == 4:
            fh.write('"%s" [color=blue,label="{%s|{%s|t:marginal}}"]\n'
                     % (memberkey, seen_members[memberkey], memberkey))
        elif memberkey not in trustdb or trustdb[memberkey] < 4:
            fh.write('"%s" [color=orange,label="{%s|{%s|t:unknown}}"]\n'
                     % (memberkey, seen_members[memberkey], memberkey))

    fh.write('}\n')


if __name__ == '__main__':
    from optparse import OptionParser

    usage = '''usage: %prog -t trustdb.dump key
    Creates a dot graph to all fully trusted keys in a trustdb
    Trustdb must first be exported using gpg --export-ownertrust
    '''

    op = OptionParser(usage=usage, version='0.1')
    op.add_option('-v', '--verbose', dest='verbose', action='store_true',
                  default=False,
                  help='Be verbose and tell us what you are doing')
    op.add_option('-t', '--ownertrust-dump', dest='trustfile',
                  default='./ownertrust.out',
                  help='Output of gpg --export-ownertrust, default=%default')
    op.add_option('-o', '--output', dest='dotgraph',
                  default=None,
                  help='Write the DOT graph into this file (default stdout)')

    opts, args = op.parse_args()

    if not opts.trustfile:
        op.error('You must provide the path to ownertrust dump')

    if len(args) != 1:
        op.error('Please provide key to trace')

    analyze(args[0], opts.trustfile, opts.dotgraph)
