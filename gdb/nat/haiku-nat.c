/* Internal interfaces for the Haiku code.

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

/* Wrap this to prevent name clashes with a similarly named function in
   Haiku's system headers.  */
#define debug_printf haiku_debug_printf
#define debug_vprintf haiku_debug_vprintf

#include "gdbsupport/common-defs.h"

#include "diagnostics.h"
#include "target/waitstatus.h"

#undef debug_printf
#undef debug_vprintf
/* Now we can safely include Haiku headers.  */

#include "nat/haiku-nat.h"
#include "nat/haiku-nub-message.h"

#include <errno.h>
#include <string.h>

#include <map>
#include <memory>
#include <queue>

#include <debugger.h>

#define RETURN_IF_FAIL(exp)                                                   \
  do                                                                          \
    {                                                                         \
      status_t status = (exp);                                                \
      if (status < B_OK)                                                      \
        return status;                                                        \
    }                                                                         \
  while (0)

#define RETURN_VALUE_AND_SET_ERRNO_IF_FAIL(exp, val)                          \
  do                                                                          \
    {                                                                         \
      status_t status = (exp);                                                \
      if (status < B_OK)                                                      \
        {                                                                     \
          errno = status;                                                     \
          return (val);                                                       \
        }                                                                     \
    }                                                                         \
  while (0)

#define RETURN_AND_SET_ERRNO_IF_FAIL(exp)                                     \
  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (exp, -1)

namespace haiku_nat
{

class team_debug_context;

/* Expose this instead of forward declaring
   the whole team_debug_context. */
template <debug_nub_message message>
[[nodiscard]]
std::enable_if_t<std::is_same_v<haiku_nub_message_reply<message>, void>,
                 status_t> team_send (const team_debug_context *context,
                                      haiku_nub_message_data<message> &&data);

template <debug_nub_message message>
[[nodiscard]]
std::enable_if_t<!std::is_same_v<haiku_nub_message_reply<message>, void>,
                 status_t> team_send (const team_debug_context *context,
                                      haiku_nub_message_data<message> &&data,
                                      haiku_nub_message_reply<message> &reply);

class thread_debug_context
{
private:
  enum signal_status
  {
    /* This signal is recorded in an actual signal event
       and will arrive to the thread when resumed.  */
    SIGNAL_ACTUAL,
    /* This signal is forcasted to be sent if the current event is not ignored.
       (e.g. an exception has occurred).
       It is not from an actual signal event.  */
    SIGNAL_FORECASTED,
    /* This signal (often SIGTRAP) is faked in the interface we provide to GDB.
       It will not and should not be sent for this event.  */
    SIGNAL_FAKED
  };

  team_debug_context *m_team = nullptr;
  thread_id m_thread = -1;
  bool m_stopped = false;
  bool m_deleted = false;
  /* If non-zero, the signal that Haiku would send this thread when resumed. */
  int m_signal = 0;
  signal_status m_signal_status;
  struct
  {
    debug_cpu_state data;
    bool valid = false;
    bool dirty = false;
  } m_cpu_state;
  std::queue<std::shared_ptr<target_waitstatus> > m_events;

public:
  thread_debug_context () = default;
  thread_debug_context (const thread_debug_context &other) = delete;
  thread_debug_context (thread_debug_context &&other)
      : m_team (other.m_team), m_thread (other.m_thread),
        m_stopped (other.m_stopped), m_deleted (other.m_deleted),
        m_signal (other.m_signal), m_signal_status (other.m_signal_status),
        m_cpu_state (other.m_cpu_state), m_events (std::move (other.m_events))
  {
    other.m_team = nullptr;
    other.m_thread = -1;
    other.m_stopped = false;
    other.m_deleted = false;
    other.m_signal = 0;
    other.m_cpu_state.valid = false;
  }

  [[nodiscard]]
  status_t
  initialize (thread_id thread, team_debug_context *team)
  {
    if (m_thread >= 0)
      return B_NOT_ALLOWED;
    m_thread = thread;
    m_team = team;
    return B_OK;
  }

  bool
  has_events () const
  {
    return m_thread >= 0 && !m_events.empty ();
  }
  bool
  can_resume () const
  {
    return m_stopped && (has_events () || !m_deleted);
  }
  bool
  is_stopped () const
  {
    return m_stopped;
  }
  bool
  is_deleted () const
  {
    return m_deleted;
  }

  thread_id
  thread () const
  {
    return m_thread;
  }

  [[nodiscard]]
  status_t
  enqueue (debug_debugger_message message,
           const debug_debugger_message_data &data,
           const std::function<
               status_t (const std::shared_ptr<target_waitstatus> &)> callback)
  {
    if (m_thread < 0)
      return B_NOT_INITIALIZED;

    std::shared_ptr<target_waitstatus> gdbstatus;

    const auto make = [&] () -> target_waitstatus & {
      gdbstatus = std::make_shared<target_waitstatus> ();
      return *gdbstatus;
    };

    const auto add = [&] () {
      RETURN_IF_FAIL (callback (gdbstatus));
      m_events.emplace (std::move (gdbstatus));
      return B_OK;
    };

    const auto store_cpu = [&] (const debug_cpu_state &state) {
      m_cpu_state.data = state;
      m_cpu_state.valid = true;
      m_cpu_state.dirty = false;
    };

    /* For all known Haiku debugger events,
       the related thread should be stopped. */
    m_stopped = true;

    /* Default signal status.  */
    m_signal = SIGTRAP;
    m_signal_status = SIGNAL_FAKED;

    switch (message)
      {
      case B_DEBUGGER_MESSAGE_THREAD_DEBUGGED:
        HAIKU_TRACE ("THREAD_DEBUGGED: team=%i, thread=%i", data.origin.team,
                     data.origin.thread);
        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_DEBUGGER_CALL:
        HAIKU_TRACE ("DEBUGGER_CALL: team=%i, thread=%i, message=%p",
                     data.origin.team, data.origin.thread,
                     data.debugger_call.message);
        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_BREAKPOINT_HIT:
        HAIKU_TRACE ("BREAKPOINT_HIT: team=%i, thread=%i", data.origin.team,
                     data.origin.thread);

        store_cpu (data.breakpoint_hit.cpu_state);

        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_WATCHPOINT_HIT:
        HAIKU_TRACE ("WATCHPOINT_HIT: team=%i, thread=%i", data.origin.team,
                     data.origin.thread);

        store_cpu (data.watchpoint_hit.cpu_state);

        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_SINGLE_STEP:
        HAIKU_TRACE ("SINGLE_STEP: team=%i, thread=%i", data.origin.team,
                     data.origin.thread);

        store_cpu (data.single_step.cpu_state);

        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_PRE_SYSCALL:
        HAIKU_TRACE ("PRE_SYSCALL: team=%i, thread=%i, syscall=%i",
                     data.origin.team, data.origin.thread,
                     data.pre_syscall.syscall);
        make ().set_syscall_entry (data.pre_syscall.syscall);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_POST_SYSCALL:
        HAIKU_TRACE ("POST_SYSCALL: team=%i, thread=%i, syscall=%i",
                     data.origin.team, data.origin.thread,
                     data.post_syscall.syscall);
        make ().set_syscall_return (data.post_syscall.syscall);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_SIGNAL_RECEIVED:
        HAIKU_TRACE (
            "SIGNAL_RECEIVED: team=%i, thread=%i, signal=%i, deadly=%i",
            data.origin.team, data.origin.thread, data.signal_received.signal,
            data.signal_received.deadly);

        m_signal = data.signal_received.signal;
        m_signal_status = SIGNAL_ACTUAL;

        if (data.signal_received.deadly)
          {
            make ().set_signalled (
                gdb_signal_from_host (data.signal_received.signal));
            RETURN_IF_FAIL (add ());
          }
        else
          {
            make ().set_stopped (
                gdb_signal_from_host (data.signal_received.signal));
            RETURN_IF_FAIL (add ());
          }
        break;
      case B_DEBUGGER_MESSAGE_EXCEPTION_OCCURRED:
        HAIKU_TRACE (
            "EXCEPTION_OCCURRED: team=%i, thread=%i, exception=%i, signal=%i",
            data.origin.team, data.origin.thread,
            (int)data.exception_occurred.exception,
            data.exception_occurred.signal);

        m_signal = data.exception_occurred.signal;
        m_signal_status = SIGNAL_FORECASTED;

        make ().set_stopped (
            gdb_signal_from_host (data.exception_occurred.signal));
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_TEAM_CREATED:
        HAIKU_TRACE ("TEAM_CREATED: team=%i, thread=%i, new_team=%i",
                     data.origin.team, data.origin.thread,
                     data.team_created.new_team);

        make ().set_forked (ptid_t (data.team_created.new_team));
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_TEAM_DELETED:
        HAIKU_TRACE ("TEAM_DELETED: team=%i, status=%i", data.origin.team,
                     data.team_deleted.status);

        /* Thread should also be gone with the team.  */
        m_deleted = true;

        if (data.team_deleted.signal >= 0)
          make ().set_signalled (
              gdb_signal_from_host (data.team_deleted.signal));
        else
          make ().set_exited (data.team_deleted.status);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_TEAM_EXEC:
        HAIKU_TRACE ("TEAM_EXEC: team=%i, thread=%i, image_event=%i",
                     data.origin.team, data.origin.thread,
                     data.team_exec.image_event);

        /* This event does not give us the full path of the executable,
           which the corresponding GDB event requires.

           Furthermore, after this event, the new process does not take
           control yet. We would need to wait for runtime_loader to
           complete its rituals and finally fire up a IMAGE_CREATED
           event for the main app executable.

           However, this event does nuke all existing mapped images,
           so we fire a TARGET_WAITKIND_LOADED here to cause GDB to reset
           its library list.  */
        make ().set_loaded ();
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_THREAD_CREATED:
        HAIKU_TRACE ("THREAD_CREATED: team=%i, thread=%i, new_thread=%i",
                     data.origin.team, data.origin.thread,
                     data.thread_created.new_thread);

        make ().set_thread_created ();
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_THREAD_DELETED:
        HAIKU_TRACE ("THREAD_DELETED: team=%i, thread=%i, status=%i",
                     data.origin.team, data.origin.thread,
                     data.thread_deleted.status);

        /* There might still be events for this thread, but we can no longer
           resume or otherwise communicate with the thread.  */
        m_deleted = true;

        make ().set_thread_exited (data.thread_deleted.status);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_IMAGE_CREATED:
        HAIKU_TRACE (
            "IMAGE_CREATED: team=%i, thread=%i, image_event=%i, name=%s",
            data.origin.team, data.origin.thread,
            data.image_created.image_event, data.image_created.info.name);

        make ().set_loaded ();
        RETURN_IF_FAIL (add ());

        /* The app is fully loaded. Emit an EXECD event.  */
        if (data.image_created.info.type == B_APP_IMAGE)
          {
            make ().set_execd (
                make_unique_xstrdup (data.image_created.info.name));
            RETURN_IF_FAIL (add ());

            make ().set_stopped (GDB_SIGNAL_TRAP);
            RETURN_IF_FAIL (add ());
          }

        break;
      case B_DEBUGGER_MESSAGE_IMAGE_DELETED:
        HAIKU_TRACE (
            "IMAGE_DELETED: team=%i, thread=%i, image_event=%i, name=%s",
            data.origin.team, data.origin.thread,
            data.image_deleted.image_event, data.image_deleted.info.name);

        /* Send TARGET_WAITKIND_LOADED here as well, as it causes the shared
           libraries list to be updated.  */
        make ().set_loaded ();
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_PROFILER_UPDATE:
        HAIKU_TRACE ("PROFILER_UPDATE: team=%i, thread=%i", data.origin.team,
                     data.origin.thread);

        /* How did we even get here?  */
        make ().set_spurious ();
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_HANDED_OVER:
        HAIKU_TRACE ("HANDED_OVER: team=%i, thread=%i, causing_thread=%i",
                     data.origin.team, data.origin.thread,
                     data.handed_over.causing_thread);

        /* How did we even get here?  */
        make ().set_spurious ();
        RETURN_IF_FAIL (add ());
        break;
      default:
        HAIKU_TRACE ("Unimplemented debugger message code: %i", message);

        make ().set_spurious ();
        RETURN_IF_FAIL (add ());
        break;
      }

    return B_OK;
  }

  [[nodiscard]]
  status_t
  dequeue (target_waitstatus *ourstatus)
  {
    if (m_thread < 0)
      return B_NOT_INITIALIZED;
    if (m_events.empty ())
      return B_BUSY;

    /* Not a real dequeue request, just peeking.  */
    if (ourstatus == nullptr)
      return B_OK;

    *ourstatus = std::move (*m_events.front ());
    m_events.pop ();
    return B_OK;
  }

  [[nodiscard]]
  status_t
  resume (resume_kind kind = resume_continue, int sig = 0)
  {
    if (m_thread < 0 || m_team == nullptr)
      return B_NOT_INITIALIZED;
    if (kind == resume_stop)
      return B_BAD_VALUE;
    if (!is_stopped ())
      return B_BUSY;

    /* Let GDB run the wait loop again.  */
    if (has_events ())
      return B_OK;

    if (is_deleted ())
      return B_BAD_THREAD_ID;

    uint32 handle_event = B_THREAD_DEBUG_HANDLE_EVENT;
    bool step = kind == resume_step;
    int signal_to_send = 0;
    int signal_to_mute = 0;

    if (sig != 0)
      {
        if (m_signal != 0)
          {
            if (sig == m_signal)
              {
                /* Signal GDB wants is the same as what Haiku would send.  */
                /* We do not need to do anything.  */

                /*
                TODO: Is this neccessary? Work out what waddlesplash meant.
                if (m_signal_status == SIGNAL_FORECASTED)
                {
                  // the signal has not yet been sent, so we need to ignore
                  // it only in this case, but not in the other ones
                  signal_to_mute = m_signal;
                }
                */
              }
            else
              {
                /* Signal GDB wants is not the same as what Haiku intends.  */
                /* If the signal is not faked, we need to ignore the event. */
                if (m_signal_status != SIGNAL_FAKED)
                  handle_event = B_THREAD_DEBUG_IGNORE_EVENT;

                /* The event has already been ignored,
                   so we don't need to mute the signal.  */
              }
          }
      }
    else
      {
        if (m_signal != 0)
          {
            /* Haiku intends to send a signal,
               but GDB does not want to send anything.  */
            /* Ignore the event if that signal is not fake.  */
            if (m_signal_status != SIGNAL_FAKED)
              handle_event = B_THREAD_DEBUG_IGNORE_EVENT;
          }
        else
          {
            /* Neither Haiku nor GDB wants to send a signal.  */
          }
      }

    /* Flush CPU state if dirty.  */
    if (m_cpu_state.valid && m_cpu_state.dirty)
      {
        RETURN_IF_FAIL (team_send<B_DEBUG_MESSAGE_SET_CPU_STATE> (
            m_team, { .thread = m_thread, .cpu_state = m_cpu_state.data }));

        m_cpu_state.dirty = false;
      }

    /* Mute Haiku's pending signal if necessary.  */
    if (signal_to_mute != 0)
      {
        RETURN_IF_FAIL (team_send<B_DEBUG_MESSAGE_SET_SIGNAL_MASKS> (
            m_team,
            { .thread = m_thread,
              .ignore_mask = 0,
              .ignore_once_mask = B_DEBUG_SIGNAL_TO_MASK (signal_to_mute),
              .ignore_op = B_DEBUG_SIGNAL_MASK_OR,
              .ignore_once_op = B_DEBUG_SIGNAL_MASK_OR }));
      }

    /* Send what GDB wants.  */
    if (signal_to_send != 0)
      {
        if (send_signal (m_thread, signal_to_send) < 0)
          {
            HAIKU_TRACE ("Failed to send signal %i to thread %i: %s",
                         signal_to_send, m_thread, strerror (errno));
            return errno;
          }
      }

    /* Actually resume the thread.  */
    RETURN_IF_FAIL (team_send<B_DEBUG_MESSAGE_CONTINUE_THREAD> (
        m_team, { .thread = m_thread,
                  .handle_event = handle_event,
                  .single_step = step }));

    HAIKU_TRACE ("Sent CONTINUE_THREAD message to thread %i (handle_event=%i, "
                 "single_step=%i)",
                 m_thread, handle_event, (int)step);

    m_stopped = false;

    m_cpu_state.valid = false;

    return B_OK;
  }

  [[nodiscard]]
  status_t
  get_cpu_state (debug_cpu_state &state, bool direct = false)
  {
    if (m_thread < 0)
      return B_NOT_INITIALIZED;

    if (!is_stopped ())
      return B_BUSY;

    if (!direct && m_cpu_state.valid)
      {
        state = m_cpu_state.data;
        return B_OK;
      }

    if (is_deleted ())
      return B_BAD_THREAD_ID;

    debug_nub_get_cpu_state_reply reply;

    RETURN_IF_FAIL (team_send<B_DEBUG_MESSAGE_GET_CPU_STATE> (
        m_team, { .thread = m_thread }, reply));

    state = m_cpu_state.data = reply.cpu_state;
    m_cpu_state.valid = true;
    m_cpu_state.dirty = false;

    return B_OK;
  }

  [[nodiscard]]
  status_t
  set_cpu_state (const debug_cpu_state &state, bool direct = false)
  {
    if (m_thread < 0)
      return B_NOT_INITIALIZED;

    if (!is_stopped ())
      return B_BUSY;

    m_cpu_state.data = state;
    m_cpu_state.valid = true;
    m_cpu_state.dirty = true;

    if (!direct)
      return B_OK;

    if (is_deleted ())
      return B_BAD_THREAD_ID;

    RETURN_IF_FAIL (team_send<B_DEBUG_MESSAGE_SET_CPU_STATE> (
        m_team, { .thread = m_thread, .cpu_state = m_cpu_state.data }));

    m_cpu_state.dirty = false;

    return B_OK;
  }
};

class team_debug_context
{
private:
  team_id m_team = -1;
  port_id m_nub_port = -1;
  port_id m_debugger_port = -1;
  port_id m_reply_port = -1;
  int32 m_debug_flags = 0;
  std::map<thread_id, thread_debug_context> m_threads;
  std::queue<std::pair<thread_id, std::weak_ptr<target_waitstatus> > >
      m_events;

  /* Cleans all invalid events at the front of the queue.
     Returns true if there are no valid events left.  */
  bool
  clean_events ()
  {
    while (!m_events.empty () && m_events.front ().second.expired ())
      m_events.pop ();
    return m_events.empty ();
  }

  /* Deletes all ports.  */
  void
  delete_debug_ports ()
  {
    if (m_nub_port >= 0)
      delete_port (m_nub_port);
    m_nub_port = -1;
    if (m_reply_port >= 0)
      delete_port (m_reply_port);
    m_reply_port = -1;
    if (m_debugger_port >= 0)
      delete_port (m_debugger_port);
    m_debugger_port = -1;
  }

  [[nodiscard]]
  status_t
  set_debug_flags (int32 flags)
  {
    if (is_detached ())
      return B_NOT_ALLOWED;

    if (flags == m_debug_flags)
      return B_OK;

    RETURN_IF_FAIL (send<B_DEBUG_MESSAGE_SET_TEAM_FLAGS> ({ .flags = flags }));

    m_debug_flags = flags;

    return B_OK;
  }

public:
  team_debug_context () = default;
  team_debug_context (const team_debug_context &other) = delete;
  team_debug_context (team_debug_context &&other)
      : m_team (other.m_team), m_nub_port (other.m_nub_port),
        m_debugger_port (other.m_debugger_port),
        m_reply_port (other.m_reply_port), m_debug_flags (other.m_debug_flags),
        m_threads (std::move (other.m_threads)),
        m_events (std::move (other.m_events))
  {
    other.m_team = -1;
    other.m_nub_port = -1;
    other.m_debugger_port = -1;
    other.m_reply_port = -1;
    other.m_debug_flags = 0;
  }

  [[nodiscard]]
  status_t
  initialize (team_id team, bool load_existing)
  {
    if (m_team >= 0)
      return B_NOT_ALLOWED;

    /* Create the debugger port.  */
    /* 10 is a value taken from waddlesplash's port.  */
    m_debugger_port = create_port (10, "gdb debug");
    if (m_debugger_port < 0)
      {
        HAIKU_TRACE ("Failed to create debugger port: %s",
                     strerror (m_debugger_port));
        return m_debugger_port;
      }

    m_reply_port = create_port (10, "gdb debug reply");
    if (m_reply_port < 0)
      {
        HAIKU_TRACE ("Failed to create debugger reply port: %s",
                     strerror (m_reply_port));
        return m_reply_port;
      }

    /* Install ourselves as the team debugger.  */
    m_nub_port = install_team_debugger (team, m_debugger_port);
    if (m_nub_port < 0)
      {
        HAIKU_TRACE ("Failed to install ourselves as debugger for team %i: %s",
                     team, strerror (errno));
        return m_nub_port;
      }

    /* Set the team debug flags.  */
    RETURN_IF_FAIL (set_debug_flags (
        B_TEAM_DEBUG_SIGNALS |
        /* Only set the syscall debug flags when appropriate.
           These events come very often and can flood the debugger
           with large unneccessary messages.  */
        /* B_TEAM_DEBUG_PRE_SYSCALL | B_TEAM_DEBUG_POST_SYSCALL | */
        B_TEAM_DEBUG_TEAM_CREATION | B_TEAM_DEBUG_THREADS | B_TEAM_DEBUG_IMAGES
        | B_TEAM_DEBUG_STOP_NEW_THREADS));

    /* We have successfully initialized, now record the team.  */
    m_team = team;

    if (load_existing)
      {
        /* Load existing images.  */
        for_each_image (team, [&] (const image_info &info) {
          image_created (ptid_t (team, 0, team), info.name, info.text);
          return 0;
        });

        /* Debug and stop existing threads.  */
        for_each_thread (team, [] (const thread_info &info) {
          debug_thread (info.tid);
          return 0;
        });
      }

    HAIKU_TRACE ("Attached team debugger: team=%i, debugger_port=%i, "
                 "reply_port=%i, nub_port=%i",
                 m_team, m_debugger_port, m_reply_port, m_nub_port);

    return B_OK;
  }

  /* Checks whether this team has any events queued.  */
  bool
  has_events ()
  {
    if (m_team < 0)
      return false;
    return !clean_events ();
  }

  /* Checks whether this team is deleted or has been otherwise detached.  */
  bool
  is_detached () const
  {
    return (m_team >= 0) && (m_debugger_port < 0);
  }

  /* Getters.  */

  team_id
  team () const
  {
    return m_team;
  }

  port_id
  debugger_port () const
  {
    return m_debugger_port;
  }

  /* Message operations.  */

  template <debug_nub_message message>
  [[nodiscard]]
  std::enable_if_t<std::is_same_v<haiku_nub_message_reply<message>, void>,
                   status_t>
  send (const haiku_nub_message_data<message> &data) const
  {
    return haiku_send_nub_message<message> (m_nub_port, data);
  }

  template <debug_nub_message message>
  [[nodiscard]]
  std::enable_if_t<!std::is_same_v<haiku_nub_message_reply<message>, void>,
                   haiku_nub_message_reply<message> >
  send (haiku_nub_message_data<message> &&data) const
  {
    data.reply_port = m_reply_port;
    return haiku_send_nub_message<message> (m_nub_port, data);
  }

  template <debug_nub_message message>
  [[nodiscard]]
  std::enable_if_t<!std::is_same_v<haiku_nub_message_reply<message>, void>,
                   status_t>
  send (haiku_nub_message_data<message> &&data,
        haiku_nub_message_reply<message> &reply) const
  {
    data.reply_port = m_reply_port;
    return haiku_send_nub_message<message> (m_nub_port, data, reply);
  }

  [[nodiscard]]
  ssize_t
  read (debug_debugger_message &message, debug_debugger_message_data &data,
        bool block = true) const
  {
    if (m_team < 0)
      return B_NOT_INITIALIZED;

    if (is_detached ())
      return B_NOT_ALLOWED;

    ssize_t bytes_read;
    int32 code;

    do
      {
        bytes_read
            = read_port_etc (m_debugger_port, &code, &data, sizeof (data),
                             (block ? 0 : B_RELATIVE_TIMEOUT), 0);
      }
    while (bytes_read == B_INTERRUPTED);

    message = (debug_debugger_message)code;

    return bytes_read;
  }

  bool
  thread_alive (ptid_t ptid) const
  {
    if (m_team < 0)
      return false;

    if (is_detached ())
      return false;

    if (ptid.tid_p ())
      {
        auto it = m_threads.find (ptid.tid ());
        if (it == m_threads.end ())
          return false;

        return !it->second.is_deleted ();
      }

    for (const auto &[thread, thread_context] : m_threads)
      {
        if (!thread_context.is_deleted ())
          return true;
      }

    return false;
  }

  [[nodiscard]]
  status_t
  get_cpu_state (ptid_t ptid, debug_cpu_state &state, bool direct = false)
  {
    if (m_team < 0)
      return B_NOT_INITIALIZED;

    auto it = m_threads.find (ptid.tid ());
    if (it == m_threads.end ())
      return B_BAD_THREAD_ID;

    return it->second.get_cpu_state (state, direct);
  }

  [[nodiscard]]
  status_t
  set_cpu_state (ptid_t ptid, const debug_cpu_state &state,
                 bool direct = false)
  {
    if (m_team < 0)
      return B_NOT_INITIALIZED;

    auto it = m_threads.find (ptid.tid ());
    if (it == m_threads.end ())
      return B_BAD_THREAD_ID;

    return it->second.set_cpu_state (state, direct);
  }

  /* Resumes each thread in the current team unless it stil has pending
     events.  */
  [[nodiscard]]
  status_t
  resume ()
  {
    if (m_team < 0)
      return B_NOT_INITIALIZED;

    for (auto &[thread, thread_context] : m_threads)
      RETURN_IF_FAIL (thread_context.resume ());

    return B_OK;
  }

  /* GDB interface.  */

  /* Implement the resume target_ops method.  */
  [[nodiscard]]
  status_t
  resume (ptid_t ptid, resume_kind kind, int sig)
  {
    if (m_team < 0)
      return B_NOT_INITIALIZED;

    bool catching_syscalls = is_catching_syscalls_for (ptid_t (m_team));

    int resume_flags = m_debug_flags;
    if (catching_syscalls)
      resume_flags |= B_TEAM_DEBUG_PRE_SYSCALL | B_TEAM_DEBUG_POST_SYSCALL;
    else
      resume_flags &= ~(B_TEAM_DEBUG_PRE_SYSCALL | B_TEAM_DEBUG_POST_SYSCALL);

    RETURN_IF_FAIL (set_debug_flags (resume_flags));

    bool any_thread = !ptid.tid_p ();

    if (any_thread)
      {
        for (auto &[thread, thread_context] : m_threads)
          if (thread_context.can_resume ())
            RETURN_IF_FAIL (thread_context.resume (kind, sig));
      }
    else
      {
        auto it = m_threads.find (ptid.tid ());
        if (it == m_threads.end ())
          return B_BAD_THREAD_ID;
        thread_debug_context &thread_context = it->second;
        RETURN_IF_FAIL (thread_context.resume (kind, sig));
      }

    return B_OK;
  }

  /* Implement the wait target_ops method with a few differences:
     - The requested ptid is passed by parameter and the resulting ptid is
       passed back there on return.
     - The function accepts a NULL ourstatus to peek and enqueue the next port
       event without dequeuing it from the thread_debug_context.  */
  [[nodiscard]]
  status_t
  wait (ptid_t &ptid, target_waitstatus *ourstatus,
        target_wait_flags target_options)
  {
    if (m_team < 0)
      return B_NOT_INITIALIZED;

    const auto thread_dequeue = [&] (thread_debug_context &thread_context) {
      RETURN_IF_FAIL (thread_context.dequeue (ourstatus));
      ptid = ptid_t (m_team, 0, thread_context.thread ());

      /* In many cases, the dequeued event is at the front of the global
          queue.  */
      clean_events ();

      if (thread_context.is_deleted () && !thread_context.has_events ())
        {
          HAIKU_TRACE ("removing deleted thread context: team=%i, thread=%i",
                       m_team, thread_context.thread ());

          m_threads.erase (thread_context.thread ());
        }

      return B_OK;
    };

    bool any_thread = !ptid.tid_p ();

    /* Try to read queued events.  */
    if (any_thread)
      {
        if (!clean_events ())
          {
            auto [thread, weak_event] = std::move (m_events.front ());
            m_events.pop ();

            return thread_dequeue (m_threads.at (thread));
          }
      }
    else
      {
        thread_id thread = ptid.tid ();
        auto it = m_threads.find (thread);
        if (it == m_threads.end ())
          return B_BAD_THREAD_ID;
        thread_debug_context &thread_context = it->second;
        if (thread_context.has_events ())
          return thread_dequeue (thread_context);
      }

    debug_debugger_message message;
    debug_debugger_message_data data;

    bool block = !(target_options & TARGET_WNOHANG).raw ();

    /* There are no suitable queued events, read some more.  */
    while (true)
      {
        ssize_t bytes_read = read (message, data, block);

        if (!block && (bytes_read == B_WOULD_BLOCK))
          {
            ptid = null_ptid;
            return B_OK;
          }
        else if (bytes_read < B_OK)
          return bytes_read;

        gdb_assert (data.origin.team == m_team);

        HAIKU_TRACE ("Received debug message type %i.", message);

        /* Internal bookkeeping.  */
        switch (message)
          {
          case B_DEBUGGER_MESSAGE_SIGNAL_RECEIVED:
            if (!data.signal_received.deadly)
              {
                /* There's still hope...  */
                break;
              }
            /* GDB no longer wants us after seeing a
                TARGET_WAITKIND_SIGNALLED event.  */
            [[fallthrough]];
          case B_DEBUGGER_MESSAGE_TEAM_DELETED:
            /* Detach to prevent further read loops.  */
            detach (true);

            /* Set any thread value so that the event gets handled immediately
               by the code below.  */
            data.origin.thread = any_thread ? m_team : ptid.tid ();
            break;
          case B_DEBUGGER_MESSAGE_IMAGE_CREATED:
            image_created (ptid_t (data.origin.team, 0, data.origin.thread),
                           data.image_created.info.name,
                           (CORE_ADDR)data.image_created.info.text);
            break;
          case B_DEBUGGER_MESSAGE_IMAGE_DELETED:
            image_deleted (ptid_t (data.origin.team, 0, data.origin.thread),
                           data.image_deleted.info.name);
            break;
          case B_DEBUGGER_MESSAGE_TEAM_EXEC:
            /* Any pending events are meaningless.  */
            image_deleted (ptid_t (data.origin.team, 0, data.origin.thread),
                           nullptr);
            break;
          case B_DEBUGGER_MESSAGE_DEBUGGER_CALL:
            {
              CORE_ADDR message_addr = (CORE_ADDR)data.debugger_call.message;
              std::string message_string;

              debug_nub_read_memory_reply read_memory_reply;
              status_t read_memory_status = B_OK;
              size_t chars_read = 0;

              while (true)
                {
                  read_memory_status = send<B_DEBUG_MESSAGE_READ_MEMORY> (
                      { .address = (void *)message_addr,
                        B_MAX_READ_WRITE_MEMORY_SIZE },
                      read_memory_reply);

                  /* Message invalid, or nothing more to read.  */
                  if (read_memory_reply.size == 0)
                    break;

                  chars_read = strnlen (read_memory_reply.data,
                                        read_memory_reply.size);

                  message_string.insert (message_string.end (),
                                         read_memory_reply.data,
                                         read_memory_reply.data + chars_read);

                  /* Nothing else to read.  */
                  if (chars_read < B_MAX_READ_WRITE_MEMORY_SIZE)
                    break;
                }

              if (read_memory_status < B_OK && message_string.empty ())
                message_string
                    = string_printf ("Thread %i called debugger(), but failed "
                                     "to get the debugger message.",
                                     (int)data.origin.thread);
              else
                message_string = string_printf (
                    "Thread %i called debugger(): %s", (int)data.origin.thread,
                    message_string.c_str ());

              debugger_output (message_string.c_str ());
            }
            break;
          case B_DEBUGGER_MESSAGE_EXCEPTION_OCCURRED:
            {
              /* Best thing we can do, since Haiku does not provide any way to
                 get the size!  */
              char buffer[1024];
              get_debug_exception_string (data.exception_occurred.exception,
                                          buffer, sizeof (buffer));

              std::string message_string
                  = string_printf ("Thread %i caused an exception: %s",
                                   (int)data.origin.thread, buffer);

              debugger_output (message_string.c_str ());
            }
            break;
          case B_DEBUGGER_MESSAGE_HANDED_OVER:
            /* This event is sent in only two cases:
               - We called B_DEBUG_MESSAGE_PREPARE_HANDOVER, and another team
               called install_team_debugger(). This should be impossible for
               GDB.
               - We started debugging a team that has previously been attached
               by someone else, usually the debug server.

               Since the event is asynchronous (data.origin.thread = -1, no
               threads are stopped), we should silently ignore it, without
               even queuing a message to any thread_context.
               */
            continue;
          }

        thread_id thread = data.origin.thread;
        gdb_assert (thread >= 0);

        auto [thread_it, thread_is_new] = m_threads.try_emplace (thread);
        thread_debug_context &thread_context = thread_it->second;

        if (thread_is_new)
          RETURN_IF_FAIL (thread_context.initialize (thread, this));

        RETURN_IF_FAIL (thread_context.enqueue (
            message, data,
            [&] (const std::shared_ptr<target_waitstatus> &event) {
              m_events.emplace (thread, std::weak_ptr (event));
              return B_OK;
            }));

        /* At this point we have at least one event to dequeue.  */
        if (any_thread || thread == ptid.tid ())
          return thread_dequeue (thread_context);
      }

    /* How did we get here?  */
    return B_BAD_VALUE;
  }

  /* Implement the detach target_ops method.  */
  status_t
  detach (bool force = false)
  {
    if (m_team < 0)
      return B_NO_INIT;
    if (is_detached ())
      return B_BAD_VALUE;

    status_t status = remove_team_debugger (m_team);

    HAIKU_TRACE ("Removed team debugger for team %i, status=%s", m_team,
                 strerror (status));

    if (status < B_OK && !force)
      return status;

    delete_debug_ports ();

    return B_OK;
  }

  /* Cleanup.  */
  ~team_debug_context ()
  {
    if (m_team >= 0 && !is_detached ())
      {
        HAIKU_TRACE ("Team %i has not been detached but forgotten.", m_team);
        detach (true);
      }
  }
};

template <debug_nub_message message>
[[nodiscard]]
std::enable_if_t<std::is_same_v<haiku_nub_message_reply<message>, void>,
                 status_t>
team_send (const team_debug_context *context,
           haiku_nub_message_data<message> &&data)
{
  return context->send<message> (
      std::forward<haiku_nub_message_data<message> > (data));
}

template <debug_nub_message message>
[[nodiscard]]
std::enable_if_t<!std::is_same_v<haiku_nub_message_reply<message>, void>,
                 status_t>
team_send (const team_debug_context *context,
           haiku_nub_message_data<message> &&data,
           haiku_nub_message_reply<message> &reply)
{
  return context->send<message> (
      std::forward<haiku_nub_message_data<message> > (data), reply);
}

static std::map<team_id, std::shared_ptr<team_debug_context> >
    team_debug_contexts;

[[nodiscard]]
static status_t
get_context (team_id team, std::shared_ptr<team_debug_context> &context)
{
  auto it = team_debug_contexts.find (team);
  if (it == team_debug_contexts.end ())
    return B_BAD_TEAM_ID;
  context = it->second;
  return B_OK;
}

static status_t
delete_context (const std::shared_ptr<team_debug_context> &context)
{
  if (team_debug_contexts.erase (context->team ()) == 0)
    return B_BAD_TEAM_ID;
  return B_OK;
}

/* See haiku-nat.h.  */

int
attach (pid_t pid, bool is_ours)
{
  HAIKU_TRACE ("pid=%i", pid);

  std::shared_ptr<team_debug_context> context
      = std::make_shared<team_debug_context> ();

  RETURN_AND_SET_ERRNO_IF_FAIL (context->initialize (pid, !is_ours));

  /* Record the debug entry.  */
  team_debug_contexts.try_emplace (pid, std::move (context));

  return 0;
}

/* See haiku-nat.h.  */

void
wait_for_debugger ()
{
  HAIKU_TRACE ();

  ::wait_for_debugger ();
}

/* See haiku-nat.h.  */

int
get_cpu_state (ptid_t ptid, void *buffer)
{
  HAIKU_TRACE ("ptid=%s, buffer=%p", ptid.to_string ().c_str (), buffer);

  std::shared_ptr<team_debug_context> context;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context));

  RETURN_AND_SET_ERRNO_IF_FAIL (
      context->get_cpu_state (ptid, *(debug_cpu_state *)buffer));

  return 0;
}

/* See haiku-nat.h.  */

int
set_cpu_state (ptid_t ptid, const void *buffer)
{
  HAIKU_TRACE ("ptid=%s, buffer=%p", ptid.to_string ().c_str (), buffer);

  std::shared_ptr<team_debug_context> context;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context));

  RETURN_AND_SET_ERRNO_IF_FAIL (
      context->set_cpu_state (ptid, *(const debug_cpu_state *)buffer));

  return 0;
}

/* See haiku-nat.h.  */

int
resume (ptid_t ptid, resume_kind kind, int sig)
{
  HAIKU_TRACE ("ptid=%s, resume_kind=%i, sig=%i", ptid.to_string ().c_str (),
               (int)kind, sig);

  if (ptid == minus_one_ptid)
    {
      for (auto &[pid, context] : team_debug_contexts)
        {
          RETURN_AND_SET_ERRNO_IF_FAIL (context->resume (ptid, kind, sig));
        }
    }
  else
    {
      std::shared_ptr<team_debug_context> context;
      RETURN_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context));

      RETURN_AND_SET_ERRNO_IF_FAIL (context->resume (ptid, kind, sig));
    }

  return 0;
}

/* See haiku-nat.h.  */

ptid_t
wait (ptid_t ptid, struct target_waitstatus *ourstatus,
      target_wait_flags target_options)
{
  HAIKU_TRACE ("ptid=%s, target_options=%i", ptid.to_string ().c_str (),
               (int)target_options.raw ());

  gdb_assert (ourstatus != nullptr);

  std::shared_ptr<team_debug_context> chosen_context;

  if (ptid == minus_one_ptid)
    {
      /* Wait for any process.  */
      bool block = !(target_options & TARGET_WNOHANG).raw ();

      std::vector<std::weak_ptr<team_debug_context> > contexts;
      std::vector<object_wait_info> wait_infos;

      while (!chosen_context)
        {
          std::size_t context_count = team_debug_contexts.size ();

          contexts.clear ();
          contexts.reserve (context_count);

          wait_infos.clear ();
          wait_infos.reserve (context_count);

          for (const auto &[team, context] : team_debug_contexts)
            {
              if (context->has_events ())
                {
                  chosen_context = context;
                  break;
                }
              contexts.emplace_back (context);
              wait_infos.emplace_back (
                  object_wait_info{ .object = context->debugger_port (),
                                    .type = B_OBJECT_TYPE_PORT,
                                    .events = B_EVENT_READ });
            }

          if (chosen_context)
            break;

          ssize_t count;

          do
            {
              count = wait_for_objects_etc (wait_infos.data (),
                                            wait_infos.size (),
                                            block ? 0 : B_RELATIVE_TIMEOUT, 0);
            }
          while (count == B_INTERRUPTED);

          if (!block && (count == B_WOULD_BLOCK || count == 0))
            {
              ourstatus->set_ignore ();
              return null_ptid;
            }
          else if (count < 0)
            {
              errno = count;
              return minus_one_ptid;
            }

          std::shared_ptr<team_debug_context> current_context;
          ptid_t wptid;
          status_t status;

          for (std::size_t i = 0; i < context_count; ++i)
            {
              if (contexts[i].expired ())
                continue;
              if ((wait_infos[i].events & B_EVENT_READ) == 0)
                continue;
              current_context = contexts[i].lock ();

              /* Peek to see if the port holds an event we actually want
                 instead of something like HANDED_OVER.  */
              wptid = ptid;
              status = current_context->wait (wptid, nullptr, TARGET_WNOHANG);

              /* The current one cannot immediately give a valid event.  */
              if (status < B_OK || wptid == null_ptid)
                continue;

              chosen_context = std::move (current_context);
              break;
            }
        }

      ptid = ptid_t (chosen_context->team ());

      HAIKU_TRACE ("chosen ptid=%s", ptid.to_string ().c_str ());
    }
  else
    {
      /* Wait for the specified process only.  */
      RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (
          get_context (ptid.pid (), chosen_context), minus_one_ptid);
    }

  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (
      chosen_context->wait (ptid, ourstatus, target_options), minus_one_ptid);

  if (chosen_context->is_detached () && !chosen_context->has_events ())
    {
      HAIKU_TRACE ("removing deleted team context: team=%i",
                   chosen_context->team ());
      /* There's nothing left. Remove this team from our records.  */
      delete_context (chosen_context);
    }

  HAIKU_TRACE ("ptid=%s, ourstatus=%s", ptid.to_string ().c_str (),
               ourstatus->to_string ().c_str ());

  return ptid;
}

/* See haiku-nat.h.  */

int
kill (pid_t pid)
{
  HAIKU_TRACE ("pid=%i", pid);

  std::shared_ptr<team_debug_context> context;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_context (pid, context));

  RETURN_AND_SET_ERRNO_IF_FAIL (kill_team (pid));

  /* Prevent future attempts to get events for the killed team.  */
  delete_context (context);

  ptid_t ptid;
  target_waitstatus ourstatus;

  /* Wait for the child to die.  */
  while (!context->is_detached ())
    {
      ptid = ptid_t (pid);

      if (!context->has_events ())
        std::ignore = context->resume (ptid, resume_continue, 0);

      gdb_assert (context->wait (ptid, &ourstatus, 0) == B_OK);
    }

  return 0;
}

/* See haiku-nat.h.  */

int
detach (pid_t pid)
{
  HAIKU_TRACE ("pid=%i", pid);

  std::shared_ptr<team_debug_context> context;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_context (pid, context));

  RETURN_AND_SET_ERRNO_IF_FAIL (context->detach ());

  delete_context (context);

  return 0;
}

/* See haiku-nat.h.  */

bool
thread_alive (ptid_t ptid)
{
  HAIKU_TRACE ("ptid=%s", ptid.to_string ().c_str ());

  std::shared_ptr<team_debug_context> context;
  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context),
                                      false);

  return context->thread_alive (ptid);
}

/* See haiku-nat.h.  */

int
read_memory (pid_t pid, CORE_ADDR memaddr, unsigned char *myaddr,
             int *sizeLeft)
{
  HAIKU_TRACE ("pid=%i, memaddr=%p, myaddr=%p, size=%i", pid, (void *)memaddr,
               myaddr, *sizeLeft);

  std::shared_ptr<team_debug_context> context;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_context (pid, context));

  debug_nub_read_memory_reply reply;

  while (*sizeLeft > 0)
    {
      RETURN_AND_SET_ERRNO_IF_FAIL (
          context->send<B_DEBUG_MESSAGE_READ_MEMORY> (
              { .address = (void *)memaddr, .size = (int32)*sizeLeft },
              reply));

      memcpy (myaddr, reply.data, reply.size);
      memaddr += reply.size;
      myaddr += reply.size;
      *sizeLeft -= reply.size;
    }

  HAIKU_TRACE ("pid=%i, memaddr=%p success", pid, (void *)memaddr);

  return 0;
}

/* See haiku-nat.h.  */

int
write_memory (pid_t pid, CORE_ADDR memaddr, const unsigned char *myaddr,
              int *sizeLeft)
{
  HAIKU_TRACE ("pid=%i, memaddr=%p, myaddr=%p, size=%i", pid, (void *)memaddr,
               myaddr, *sizeLeft);

  std::shared_ptr<team_debug_context> context;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_context (pid, context));

  debug_nub_write_memory data;
  debug_nub_write_memory_reply reply;

  while (*sizeLeft > 0)
    {
      data.address = (void *)memaddr;
      data.size = std::min (*sizeLeft, (int)B_MAX_READ_WRITE_MEMORY_SIZE);
      memcpy (data.data, myaddr, data.size);

      /* TODO: Rollback if attempt failed?  */
      RETURN_AND_SET_ERRNO_IF_FAIL (
          context->send<B_DEBUG_MESSAGE_WRITE_MEMORY> (std::move (data),
                                                       reply));

      memaddr += reply.size;
      myaddr += reply.size;
      *sizeLeft -= reply.size;
    }

  HAIKU_TRACE ("pid=%i, memaddr=%p success", pid, (void *)memaddr);

  return 0;
}

/* See haiku-nat.h.  */

int
read_offsets (pid_t pid, CORE_ADDR *text, CORE_ADDR *data)
{
  HAIKU_TRACE ("pid=%i", pid);

  return for_each_image (
      pid,
      [&] (const image_info &info) {
        if (!info.is_main_executable)
          return 0;

        *text = info.text;
        *data = info.data - info.text_size;

        return 1;
      },
      true);
}

/* See haiku-nat.h.  */

bool
thread_stopped (ptid_t ptid)
{
  HAIKU_TRACE ("ptid=%s", ptid.to_string ().c_str ());

  std::shared_ptr<team_debug_context> context;
  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context),
                                      false);

  status_t status = context
                        ->send<B_DEBUG_MESSAGE_GET_CPU_STATE> (
                            { .thread = (thread_id)ptid.tid () })
                        .error;

  HAIKU_TRACE ("ptid=%s, status=%s", ptid.to_string ().c_str (),
               strerror (status));

  if (status >= B_OK)
    {
      /* Operation only succeeds when thread is stopped.  */
      return true;
    }
  else if (status == B_BAD_THREAD_STATE)
    {
      /* This occurs when thread is not stopped.  */
      return false;
    }
  else
    {
      /* Some other error.  */
      errno = status;
      return false;
    }
}

/* See haiku-nat.h.  */

const char *
pid_to_exec_file (pid_t pid)
{
  HAIKU_TRACE ("pid=%i", pid);

  const char *result = nullptr;

  for_each_image (
      pid,
      [&] (const image_info &info) {
        if (!info.is_main_executable)
          return 0;

        result = info.name;

        return 1;
      },
      true);

  return result;
}

/* See haiku-nat.h.  */

const char *
thread_name (ptid_t ptid)
{
  HAIKU_TRACE ("ptid=%s", ptid.to_string ().c_str ());

  static ::thread_info info;
  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (get_thread_info (ptid.tid (), &info),
                                      nullptr);

  HAIKU_TRACE ("ptid=%s, name=%s", ptid.to_string ().c_str (), info.name);

  return info.name;
}

/* See haiku-nat.h.  */

std::string
pid_to_str (ptid_t ptid)
{
  HAIKU_TRACE ("ptid=%s", ptid.to_string ().c_str ());

  union
  {
    ::team_info team;
    ::thread_info thread;
  };

  bool team_valid = get_team_info (ptid.pid (), &team) == B_OK;

  std::string result
      = team_valid ? string_printf ("team %d (%s)", ptid.pid (), team.name)
                   : string_printf ("team %d", ptid.pid ());

  if (!ptid.tid_p ())
    return result;

  bool thread_valid
      = team_valid && (get_thread_info (ptid.tid (), &thread) == B_OK);

  result += thread_valid
                ? string_printf (" thread %ld (%s)", ptid.tid (), thread.name)
                : string_printf (" thread %ld", ptid.tid ());

  return result;
}

/* See haiku-nat.h.  */

int
stop (ptid_t ptid)
{
  /* Stops specific thread if tid is non-zero.
     Otherwise stops whole process.  */
  if (ptid.tid_p ())
    {
      RETURN_AND_SET_ERRNO_IF_FAIL (debug_thread (ptid.tid ()));
      return 0;
    }
  else
    {
      return for_each_thread (ptid.pid (), [] (const thread_info &info) {
        RETURN_AND_SET_ERRNO_IF_FAIL (debug_thread (info.tid));
        return 0;
      });
    }
}

/* See haiku-nat.h.  */

int
for_each_image (pid_t pid,
                const std::function<int (const image_info &info)> &callback,
                bool needs_one)
{
  static ::image_info haiku_info;
  static image_info info;

  int32 cookie = 0;

  while (get_next_image_info (pid, &cookie, &haiku_info) == B_OK)
    {
      if (strcmp (haiku_info.name, "commpage") == 0)
        continue;

      info.text = (CORE_ADDR)haiku_info.text;
      info.text_size = (ULONGEST)haiku_info.text_size;
      info.data = (CORE_ADDR)haiku_info.data;
      info.data_size = (ULONGEST)haiku_info.data_size;
      info.name = haiku_info.name;
      info.is_main_executable = haiku_info.type == B_APP_IMAGE;

      switch (callback (info))
        {
        case -1:
          return -1;
        case 0:
          continue;
        case 1:
          return 0;
        }
    }

  if (needs_one)
    {
      errno = B_BAD_VALUE;
      return -1;
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_area (pid_t pid,
               const std::function<int (const area_info &info)> &callback)
{
  static ::area_info haiku_info;
  static area_info info;

  ssize_t cookie = 0;

  while (get_next_area_info (pid, &cookie, &haiku_info) == B_OK)
    {
      info.low = (CORE_ADDR)haiku_info.address;
      info.high = (CORE_ADDR)haiku_info.address + haiku_info.size;
      info.can_read = haiku_info.protection & B_READ_AREA;
      info.can_write = haiku_info.protection & B_WRITE_AREA;

      switch (callback (info))
        {
        case -1:
          return -1;
        case 0:
          continue;
        case 1:
          return 0;
        }
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_thread (pid_t pid,
                 const std::function<int (const thread_info &info)> &callback)
{
  static ::thread_info haiku_info;
  static thread_info info;

  int32 cookie = 0;

  while (get_next_thread_info (pid, &cookie, &haiku_info) == B_OK)
    {
      info.tid = haiku_info.thread;

      switch (callback (info))
        {
        case -1:
          return -1;
        case 0:
          continue;
        case 1:
          return 0;
        }
    }

  return 0;
}

}
