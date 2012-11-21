#!/usr/bin/python
# -*- coding: utf-8 -*-

# - title        : Upload for Swift(Rackspace Cloud Files)
# - description  : Want to upload a bunch files to cloud files? This will do it.
# - License      : GPLv3+
# - author       : Kevin Carter
# - date         : 2011-11-09
# - usage        : python turbolift.local.py
# - notes        : This is a Swift(Rackspace Cloud Files) Upload Script
# - Python       : >= 2.6

"""
License Inforamtion
    
This software has no warranty, it is provided 'as is'. It is your responsibility
to validate the behavior of the routines and its accuracy using the code provided.
Consult the GNU General Public license for further details (see GNU General Public License).
    
http://www.gnu.org/licenses/gpl.html
"""

import os
import sys

possible_topdir = \
    os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                     os.pardir, os.pardir))

if os.path.exists(os.path.join(possible_topdir, 'turbolift',
                  '__init__.py')):
    sys.path.insert(0, possible_topdir)

from turbolift import executable
executable.run_turbolift()