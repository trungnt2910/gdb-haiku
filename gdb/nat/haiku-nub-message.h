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

#ifndef NAT_HAIKU_NUB_MESSAGE_H
#define NAT_HAIKU_NUB_MESSAGE_H

#include "gnulib/config.h"

#include <type_traits>

#include <debugger.h>

extern status_t haiku_send_nub_message (port_id nub_port, port_id reply_port,
                                        debug_nub_message message,
                                        const void *data, int data_size,
                                        void *reply, int reply_size);

template <debug_nub_message message> class haiku_nub_message_traits
{
};

#define HAIKU_ASSOCIATE_MESSAGE_DATA(message, data)                           \
  template <> class haiku_nub_message_traits<message>                         \
  {                                                                           \
  public:                                                                     \
    typedef data data_type;                                                   \
    typedef void reply_type;                                                  \
  }

#define HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY(message, data)                \
  template <> class haiku_nub_message_traits<message>                         \
  {                                                                           \
  public:                                                                     \
    typedef data data_type;                                                   \
    typedef data##_reply reply_type;                                          \
  }

HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_MESSAGE_READ_MEMORY,
                                         debug_nub_read_memory);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_MESSAGE_WRITE_MEMORY,
                                         debug_nub_write_memory);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_SET_TEAM_FLAGS,
                              debug_nub_set_team_flags);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_SET_THREAD_FLAGS,
                              debug_nub_set_thread_flags);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_CONTINUE_THREAD,
                              debug_nub_continue_thread);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_SET_CPU_STATE,
                              debug_nub_set_cpu_state);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_MESSAGE_GET_CPU_STATE,
                                         debug_nub_get_cpu_state);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_MESSAGE_SET_BREAKPOINT,
                                         debug_nub_set_breakpoint);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_CLEAR_BREAKPOINT,
                              debug_nub_clear_breakpoint);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_MESSAGE_SET_WATCHPOINT,
                                         debug_nub_set_watchpoint);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_CLEAR_WATCHPOINT,
                              debug_nub_clear_watchpoint);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_SET_SIGNAL_MASKS,
                              debug_nub_set_signal_masks);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_MESSAGE_GET_SIGNAL_MASKS,
                                         debug_nub_get_signal_masks);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_MESSAGE_SET_SIGNAL_HANDLER,
                              debug_nub_set_signal_handler);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_MESSAGE_GET_SIGNAL_HANDLER,
                                         debug_nub_get_signal_handler);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_START_PROFILER,
                                         debug_nub_start_profiler);
HAIKU_ASSOCIATE_MESSAGE_DATA (B_DEBUG_STOP_PROFILER, debug_nub_stop_profiler);
HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY (B_DEBUG_WRITE_CORE_FILE,
                                         debug_nub_write_core_file);

#undef HAIKU_ASSOCIATE_MESSAGE_DATA
#undef HAIKU_ASSOCIATE_MESSAGE_DATA_WITH_REPLY

template <debug_nub_message message>
using haiku_nub_message_data =
    typename haiku_nub_message_traits<message>::data_type;

template <debug_nub_message message>
using haiku_nub_message_reply =
    typename haiku_nub_message_traits<message>::reply_type;

template <debug_nub_message message>
std::enable_if_t<std::is_same_v<haiku_nub_message_reply<message>, void>,
                 status_t>
haiku_send_nub_message (port_id nub_port,
                        const haiku_nub_message_data<message> &data)
{
  return haiku_send_nub_message (nub_port, -1, message, &data, sizeof (data),
                                 nullptr, 0);
}

template <debug_nub_message message>
std::enable_if_t<!std::is_same_v<haiku_nub_message_reply<message>, void>,
                 haiku_nub_message_reply<message> >
haiku_send_nub_message (port_id nub_port,
                        const haiku_nub_message_data<message> &data)
{
  haiku_nub_message_reply<message> reply;
  status_t result
      = haiku_send_nub_message (nub_port, data.reply_port, message, &data,
                                sizeof (data), &reply, sizeof (reply));
  if (result >= B_OK)
    return reply;

  reply.error = result;
  return reply;
}

template <debug_nub_message message>
std::enable_if_t<!std::is_same_v<haiku_nub_message_reply<message>, void>,
                 status_t>
haiku_send_nub_message (port_id nub_port,
                        const haiku_nub_message_data<message> &data,
                        haiku_nub_message_reply<message> &reply)
{
  status_t result
      = haiku_send_nub_message (nub_port, data.reply_port, message, &data,
                                sizeof (data), &reply, sizeof (reply));
  return (result < B_OK) ? result : reply.error;
}

#endif /* NAT_HAIKU_NUB_MESSAGE_H */
