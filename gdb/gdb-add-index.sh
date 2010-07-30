#! /bin/sh

# Add a .gdb_index section to a file.

# Copyright (C) 2010 Free Software Foundation, Inc.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

file="$1"
dir="${file%/*}"

gdb --batch-silent -ex "file $file" -ex "save gdb-index $dir"

if test -f "${file}.gdb-index"; then
   objcopy --add-section .gdb_index="${file}.gdb-index" --set-section-flags .gdb_index=readonly "$file" "$file"
   rm -f "${file}.gdb-index"
fi

exit 0
