#!/usr/bin/env python3
#
# Copyright 2021, Andreas Ziegler <andreas.ziegler@fau.de>
#
# This file is part of shrinkelf.
#
# shrinkelf is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# shrinkelf is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with shrinkelf.  If not, see <http://www.gnu.org/licenses/>.

import os
import shutil
import subprocess
import sys
import time

from librarytrader.librarystore import LibraryStore

shrinkelf = '{}/shrinkelf.py'.format(os.path.dirname(sys.argv[0]))
solver = ''

print('Usage: {} <LibraryStore file> <output directory> [z3|gurobi|]'.format(os.path.basename(sys.argv[0])))
store_path = sys.argv[1]
output_dir = sys.argv[2]
if len(sys.argv) > 3:
    solver = sys.argv[3]

solver_parameters = []
if solver in ('gurobi', 'z3'):
    solver_parameters = ['-p', solver]

store = LibraryStore()
store.load(store_path)
# Create output directory if it does not exist
os.makedirs(output_dir, exist_ok=True)

tailor_dir = 'tailored_libs_{}/'.format(os.path.basename(store_path))
stats_file = '{}/stats.csv'.format(tailor_dir)
run_times = {}

for library in store.get_library_objects():
    file_to_tailor = '{}/{}'.format(tailor_dir, library.fullname)
    if not os.path.exists(file_to_tailor):
        continue

    # Output to <output_dir>/<fullname>
    bname = os.path.basename(file_to_tailor)
    out_path = os.path.join(output_dir, library.fullname.lstrip('/'))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    keep_file = 'keep_file_{}'.format(bname)

    command_list = [shrinkelf, '-K', keep_file, '-o', out_path,
                    *solver_parameters, file_to_tailor]
    print('Running shrinkelf on {}'.format(bname))
    time_before = time.time()
    res = subprocess.run(command_list)
    if res.returncode != 0:
        print("Error for {}".format(bname))

    running_time = time.time() - time_before

    run_times[library.fullname] = running_time

# Generate symlinks in appropiate directories
for key, value in store.items():
    if isinstance(value, str):
        link_path = os.path.join(tailor_dir, key[1:])
        if not os.path.islink(link_path):
            continue
        target_file = os.path.join(output_dir, key.lstrip('/'))
        if os.path.islink(target_file):
            print('symbolic link already exists: {}'.format(target_file))
            continue
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        shutil.copy(link_path, target_file, follow_symlinks=False)

with open(stats_file, 'r') as fd:
    lines = [l.strip() for l in fd.readlines()]
    for idx, line in enumerate(lines):
        if idx == 0:
            lines[0] += ',filesize after,shrinkelf time'
            continue

        filename = line.split(',')[0]
        full_path = os.path.join(output_dir, filename.lstrip('/'))
        if os.path.isfile(full_path):
            if filename not in run_times:
                print('WARNING: no run times for {}'.format(filename))
                lines[idx] += ',0,0'
                continue
            else:
                lines[idx] += ',{},{}'.format(os.stat(full_path).st_size,
                                              run_times[filename])
        else:
            print('WARNING: no shrunk file for {}'.format(filename))
            lines[idx] += ',{},{}'.format(0, 0)

    with open(os.path.join(output_dir, 'stats_full.csv'), 'w') as outfd:
        for line in lines:
            outfd.write(line + '\n')
