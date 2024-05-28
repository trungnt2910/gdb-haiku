/* Haiku nub messages support.

   Copyright (C) 2024 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "haiku-nub-message.h"

status_t
haiku_send_nub_message (port_id nub_port, port_id reply_port,
                        debug_nub_message message, const void *data,
                        int data_size, void *reply, int reply_size)
{
  /* Send message.  */
  while (true)
    {
      status_t result = write_port (nub_port, message, data, data_size);
      if (result == B_OK)
        break;
      if (result != B_INTERRUPTED)
        return result;
    }

  if (!reply)
    return B_OK;

  /* Read reply.  */
  while (true)
    {
      int32 code;
      ssize_t bytesRead = read_port (reply_port, &code, reply, reply_size);
      if (bytesRead > 0)
        return B_OK;
      if (bytesRead != B_INTERRUPTED)
        return bytesRead;
    }
}
