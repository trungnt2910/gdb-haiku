--  Copyright 2012-2013 Free Software Foundation, Inc.
--
--  This program is free software; you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation; either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.

with Pck; use Pck;

procedure A is
   Nnn : String := "12345";
   Www : Wide_String := "12345";
   Rws : Wide_Wide_String := "12345";
begin
   Do_Nothing (Nnn'Address);  -- STOP
   Do_Nothing (Www'Address);
   Do_Nothing (Rws'Address);
end A;
