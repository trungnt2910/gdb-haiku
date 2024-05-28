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
#include "gdbsupport/event-pipe.h"
#include "gdbsupport/gdb_signals.h"

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
#include <mutex>
#include <queue>
#include <set>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <debugger.h>
#include <elf.h>

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

/* ELF definitions.  */

#if B_HAIKU_32_BIT
typedef Elf32_Sym elf_sym;
#define ELF_ST_TYPE ELF32_ST_TYPE
#elif B_HAIKU_64_BIT
typedef Elf64_Sym elf_sym;
#define ELF_ST_TYPE ELF64_ST_TYPE
#endif

/* Private structures.  */

/* Derived from headers/private/system/vfs_defs.h.  */
struct fd_info
{
  int number;
  int32 open_mode;
  dev_t device;
  ino_t node;
};

/* Derived from headers/private/net/net_stat.h.  */
struct net_stat
{
  int family;
  int type;
  int protocol;
  char state[B_OS_NAME_LENGTH];
  team_id owner;
  struct sockaddr_storage address;
  struct sockaddr_storage peer;
  size_t receive_queue_size;
  size_t send_queue_size;
};

/* Private syscalls from headers/private/system/syscalls.h.
   Import them as weak symbols only since their names may change anytime.  */

extern "C" status_t _kern_entry_ref_to_path (dev_t device, ino_t inode,
                                             const char *leaf, char *userPath,
                                             size_t pathLength)
    __attribute__ ((weak));

extern "C" status_t _kern_get_next_fd_info (team_id team, uint32 *_cookie,
                                            fd_info *info, size_t infoSize)
    __attribute__ ((weak));

extern "C" status_t _kern_get_next_socket_stat (int family, uint32 *cookie,
                                                struct net_stat *stat)
    __attribute__ ((weak));

extern "C" status_t _kern_read_kernel_image_symbols (
    image_id id, elf_sym *symbolTable, int32 *_symbolCount, char *stringTable,
    size_t *_stringTableSize, addr_t *_imageDelta) __attribute__ ((weak));

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

/* Utility function, defined below.  */
static void convert_image_info (const ::image_info &haiku_info,
                                image_info &info);

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
  /* Created instead of attached or otherwise existing.  */
  bool m_created = false;
  /* True if main executable has been unloaded.  */
  bool m_unloaded = false;
  /* True if we have forced this thread to stop through target_stop.  */
  bool m_force_stopped = false;
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
        m_created (other.m_created), m_unloaded (other.m_unloaded),
        m_force_stopped (other.m_force_stopped), m_signal (other.m_signal),
        m_signal_status (other.m_signal_status),
        m_cpu_state (other.m_cpu_state), m_events (std::move (other.m_events))
  {
    other.m_team = nullptr;
    other.m_thread = -1;
    other.m_stopped = false;
    other.m_deleted = false;
    other.m_created = false;
    other.m_unloaded = false;
    other.m_force_stopped = false;
    other.m_signal = 0;
    other.m_cpu_state.valid = false;
  }

  [[nodiscard]]
  status_t
  initialize (thread_id thread, team_debug_context *team, bool created)
  {
    if (m_thread >= 0)
      return B_NOT_ALLOWED;
    m_thread = thread;
    m_team = team;
    m_created = created;
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
        haiku_nat_debug_printf ("THREAD_DEBUGGED: team=%i, thread=%i",
                                data.origin.team, data.origin.thread);

        if (m_created)
          {
            make ().set_thread_created ();
            RETURN_IF_FAIL (add ());

            m_created = false;
          }
        else if (m_force_stopped)
          {
            /* Make sure we don't report a THREAD_DEBUGGED event caused by our
               own attempt to stop a thread using debug_thread.  */
            make ().set_spurious ();
            RETURN_IF_FAIL (add ());

            m_force_stopped = false;
          }
        else
          {
            make ().set_stopped (GDB_SIGNAL_TRAP);
            RETURN_IF_FAIL (add ());
          }
        break;
      case B_DEBUGGER_MESSAGE_DEBUGGER_CALL:
        haiku_nat_debug_printf (
            "DEBUGGER_CALL: team=%i, thread=%i, message=%p", data.origin.team,
            data.origin.thread, data.debugger_call.message);
        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_BREAKPOINT_HIT:
        haiku_nat_debug_printf ("BREAKPOINT_HIT: team=%i, thread=%i",
                                data.origin.team, data.origin.thread);

        store_cpu (data.breakpoint_hit.cpu_state);

        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_WATCHPOINT_HIT:
        haiku_nat_debug_printf ("WATCHPOINT_HIT: team=%i, thread=%i",
                                data.origin.team, data.origin.thread);

        store_cpu (data.watchpoint_hit.cpu_state);

        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_SINGLE_STEP:
        haiku_nat_debug_printf ("SINGLE_STEP: team=%i, thread=%i",
                                data.origin.team, data.origin.thread);

        store_cpu (data.single_step.cpu_state);

        make ().set_stopped (GDB_SIGNAL_TRAP);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_PRE_SYSCALL:
        haiku_nat_debug_printf ("PRE_SYSCALL: team=%i, thread=%i, syscall=%i",
                                data.origin.team, data.origin.thread,
                                data.pre_syscall.syscall);
        make ().set_syscall_entry (data.pre_syscall.syscall);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_POST_SYSCALL:
        haiku_nat_debug_printf ("POST_SYSCALL: team=%i, thread=%i, syscall=%i",
                                data.origin.team, data.origin.thread,
                                data.post_syscall.syscall);
        make ().set_syscall_return (data.post_syscall.syscall);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_SIGNAL_RECEIVED:
        haiku_nat_debug_printf (
            "SIGNAL_RECEIVED: team=%i, thread=%i, signal=%i, deadly=%i",
            data.origin.team, data.origin.thread, data.signal_received.signal,
            data.signal_received.deadly);

        m_signal = data.signal_received.signal;
        m_signal_status = SIGNAL_ACTUAL;

        /* Do NOT set the signalled event here, even when the signal is marked
           "deadly" by Haiku. GDB may still interrupt these signals and do
           something else, keeping the inferior alive. This is how debugger
           pause and interrupt operations work.  */
        make ().set_stopped (
            gdb_signal_from_host (data.signal_received.signal));
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_EXCEPTION_OCCURRED:
        haiku_nat_debug_printf (
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
        haiku_nat_debug_printf (
            "TEAM_CREATED: team=%i, thread=%i, new_team=%i", data.origin.team,
            data.origin.thread, data.team_created.new_team);

        make ().set_forked (ptid_t (data.team_created.new_team));
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_TEAM_DELETED:
        haiku_nat_debug_printf ("TEAM_DELETED: team=%i, status=%i",
                                data.origin.team, data.team_deleted.status);

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
        haiku_nat_debug_printf (
            "TEAM_EXEC: team=%i, thread=%i, image_event=%i", data.origin.team,
            data.origin.thread, data.team_exec.image_event);

        /* This event does not give us the full path of the executable,
           which the corresponding GDB event requires.

           Furthermore, after this event, the new process does not take
           control yet. We would need to wait for runtime_loader to
           complete its rituals and finally fire up a IMAGE_CREATED
           event for the main app executable.  */
        m_unloaded = true;

        make ().set_spurious ();
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_THREAD_CREATED:
        haiku_nat_debug_printf (
            "THREAD_CREATED: team=%i, thread=%i, new_thread=%i",
            data.origin.team, data.origin.thread,
            data.thread_created.new_thread);

        /* Ignore this event. GDB expects THREAD_CREATED to be owned by
           the new thread, not the old one. We report THREAD_CREATED on the
           first event owned by the new thread, which is THREAD_DEBUGGED.  */

        make ().set_spurious ();
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_THREAD_DELETED:
        haiku_nat_debug_printf (
            "THREAD_DELETED: team=%i, thread=%i, status=%i", data.origin.team,
            data.origin.thread, data.thread_deleted.status);

        /* There might still be events for this thread, but we can no longer
           resume or otherwise communicate with the thread.  */
        m_deleted = true;

        make ().set_thread_exited (data.thread_deleted.status);
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_IMAGE_CREATED:
        haiku_nat_debug_printf (
            "IMAGE_CREATED: team=%i, thread=%i, image_event=%i, name=%s",
            data.origin.team, data.origin.thread,
            data.image_created.image_event, data.image_created.info.name);

        if (m_unloaded)
          {
            /* The app is fully loaded. Emit an EXECD event.  */
            if (data.image_created.info.type == B_APP_IMAGE)
              {
                m_unloaded = false;

                make ().set_execd (
                    make_unique_xstrdup (data.image_created.info.name));
                RETURN_IF_FAIL (add ());

                /* Cause GDB to refresh its library list.  */
                make ().set_loaded ();
                RETURN_IF_FAIL (add ());
              }
            else
              {
                /* Continue ignoring until we have our executable.  */
                make ().set_spurious ();
                RETURN_IF_FAIL (add ());
              }
          }
        else
          {
            make ().set_loaded ();
            RETURN_IF_FAIL (add ());
          }

        break;
      case B_DEBUGGER_MESSAGE_IMAGE_DELETED:
        haiku_nat_debug_printf (
            "IMAGE_DELETED: team=%i, thread=%i, image_event=%i, name=%s",
            data.origin.team, data.origin.thread,
            data.image_deleted.image_event, data.image_deleted.info.name);

        if (m_unloaded)
          {
            make ().set_spurious ();
            RETURN_IF_FAIL (add ());
          }
        else
          {
            /* Send TARGET_WAITKIND_LOADED here as well, as it causes the
               shared libraries list to be updated.  */
            make ().set_loaded ();
            RETURN_IF_FAIL (add ());
          }
        break;
      case B_DEBUGGER_MESSAGE_PROFILER_UPDATE:
        haiku_nat_debug_printf ("PROFILER_UPDATE: team=%i, thread=%i",
                                data.origin.team, data.origin.thread);

        /* How did we even get here?  */
        make ().set_spurious ();
        RETURN_IF_FAIL (add ());
        break;
      case B_DEBUGGER_MESSAGE_HANDED_OVER:
        haiku_nat_debug_printf (
            "HANDED_OVER: team=%i, thread=%i, causing_thread=%i",
            data.origin.team, data.origin.thread,
            data.handed_over.causing_thread);

        /* How did we even get here?  */
        make ().set_spurious ();
        RETURN_IF_FAIL (add ());
        break;
      default:
        haiku_nat_debug_printf ("Unimplemented debugger message code: %i",
                                message);

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
            haiku_nat_debug_printf (
                "Failed to send signal %i to thread %i: %s", signal_to_send,
                m_thread, strerror (errno));
            return errno;
          }
      }

    /* Actually resume the thread.  */
    RETURN_IF_FAIL (team_send<B_DEBUG_MESSAGE_CONTINUE_THREAD> (
        m_team, { .thread = m_thread,
                  .handle_event = handle_event,
                  .single_step = step }));

    haiku_nat_debug_printf (
        "Sent CONTINUE_THREAD message to thread %i (handle_event=%i, "
        "single_step=%i)",
        m_thread, handle_event, (int)step);

    m_stopped = false;

    m_cpu_state.valid = false;

    return B_OK;
  }

  [[nodiscard]]
  status_t
  stop ()
  {
    if (is_stopped ())
      return B_OK;

    RETURN_AND_SET_ERRNO_IF_FAIL (debug_thread (m_thread));
    m_force_stopped = true;

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
  ::image_info m_app_image = { .id = -1 };
  std::map<thread_id, thread_debug_context> m_threads;
  std::set<thread_id> m_created_threads;
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
        m_app_image (std::move (other.m_app_image)),
        m_threads (std::move (other.m_threads)),
        m_created_threads (std::move (other.m_created_threads)),
        m_events (std::move (other.m_events))
  {
    other.m_team = -1;
    other.m_nub_port = -1;
    other.m_debugger_port = -1;
    other.m_reply_port = -1;
    other.m_debug_flags = 0;
    other.m_app_image.id = -1;
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
        haiku_nat_debug_printf ("Failed to create debugger port: %s",
                                strerror (m_debugger_port));
        return m_debugger_port;
      }

    m_reply_port = create_port (10, "gdb debug reply");
    if (m_reply_port < 0)
      {
        haiku_nat_debug_printf ("Failed to create debugger reply port: %s",
                                strerror (m_reply_port));
        return m_reply_port;
      }

    /* Install ourselves as the team debugger.  */
    m_nub_port = install_team_debugger (team, m_debugger_port);
    if (m_nub_port < 0)
      {
        haiku_nat_debug_printf (
            "Failed to install ourselves as debugger for team %i: %s", team,
            strerror (errno));
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
          image_created (ptid_t (team, 0, team), info);
          return 0;
        });

        /* Debug and stop existing threads.  */
        for_each_thread (team, [] (const thread_info &info) {
          debug_thread (info.tid);
          return 0;
        });
      }

    haiku_nat_debug_printf (
        "Attached team debugger: team=%i, debugger_port=%i, "
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

  /* Checks whether m_app_image is valid.  */
  bool
  has_stored_app_image () const
  {
    return m_app_image.id != -1;
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

  const ::image_info &
  app_image () const
  {
    return m_app_image;
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
      thread_id thread = thread_context.thread ();

      RETURN_IF_FAIL (thread_context.dequeue (ourstatus));
      ptid = ptid_t (m_team, 0, thread);

      /* In many cases, the dequeued event is at the front of the global
          queue.  */
      clean_events ();

      if (thread_context.is_deleted () && !thread_context.has_events ())
        {
          haiku_nat_debug_printf (
              "removing deleted thread context: team=%i, thread=%i", m_team,
              thread_context.thread ());

          m_threads.erase (thread);
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

        haiku_nat_debug_printf ("Received debug message type %i.", message);

        /* Internal bookkeeping.  */
        switch (message)
          {
          case B_DEBUGGER_MESSAGE_TEAM_DELETED:
            /* Detach to prevent further read loops.  */
            detach (true);

            /* Set any thread value so that the event gets handled immediately
               by the code below.  */
            data.origin.thread = any_thread ? m_team : ptid.tid ();
            break;
          case B_DEBUGGER_MESSAGE_THREAD_CREATED:
            m_created_threads.insert (data.thread_created.new_thread);
            break;
          case B_DEBUGGER_MESSAGE_IMAGE_CREATED:
            {
              image_info info;
              convert_image_info (data.image_created.info, info);
              info.team = data.origin.team;

              image_created (ptid_t (data.origin.team, 0, data.origin.thread),
                             info);

              if (data.image_created.info.type == B_APP_IMAGE)
                m_app_image = data.image_created.info;
            }
            break;
          case B_DEBUGGER_MESSAGE_IMAGE_DELETED:
            {
              if (data.image_deleted.info.type == B_APP_IMAGE)
                m_app_image.id = -1;

              image_info info;
              convert_image_info (data.image_deleted.info, info);
              info.team = data.origin.team;

              image_deleted (ptid_t (data.origin.team, 0, data.origin.thread),
                             info);
            }
            break;
          case B_DEBUGGER_MESSAGE_TEAM_EXEC:
            m_app_image.id = -1;

            /* Destroy the whole existing address space.  */
            image_deleted (ptid_t (data.origin.team, 0, data.origin.thread),
                           { .name = nullptr });
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
          {
            RETURN_IF_FAIL (thread_context.initialize (
                thread, this,
                /* created = */ m_created_threads.count (thread) > 0));
            m_created_threads.erase (thread);
          }

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

  /* Implement the stop target_ops method.  */
  status_t
  stop (ptid_t ptid)
  {
    /* Stops specific thread if tid is non-zero.
      Otherwise stops whole process.  */
    bool all_threads = !ptid.tid_p ();

    if (all_threads)
      {
        for (auto &[thread, thread_context] : m_threads)
          RETURN_IF_FAIL (thread_context.stop ());
      }
    else
      {
        auto it = m_threads.find (ptid.tid ());
        if (it == m_threads.end ())
          return B_BAD_THREAD_ID;
        thread_debug_context &thread_context = it->second;
        RETURN_IF_FAIL (thread_context.stop ());
      }

    return B_OK;
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

    haiku_nat_debug_printf ("Removed team debugger for team %i, status=%s",
                            m_team, strerror (status));

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
        haiku_nat_debug_printf ("Team %i has not been detached but forgotten.",
                                m_team);
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

static std::mutex team_debug_ports_lock;
static std::set<port_id> team_debug_ports;

static event_pipe pipe_to_event_loop;
static event_pipe pipe_to_worker;
static thread_id async_worker_thread = -1;

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
  haiku_nat_debug_printf ("pid=%i", pid);

  std::shared_ptr<team_debug_context> context
      = std::make_shared<team_debug_context> ();

  RETURN_AND_SET_ERRNO_IF_FAIL (context->initialize (pid, !is_ours));

  {
    std::unique_lock lock (team_debug_ports_lock);
    team_debug_ports.insert (context->debugger_port ());
  }

  /* Record the debug entry and also release the pointer.  */
  team_debug_contexts.try_emplace (pid, std::move (context));

  if (is_async_p ())
    pipe_to_worker.mark ();

  return 0;
}

/* See haiku-nat.h.  */

void
wait_for_debugger ()
{
  HAIKU_NAT_SCOPED_DEBUG_ENTER_EXIT;

  ::wait_for_debugger ();
}

/* See haiku-nat.h.  */

int
get_cpu_state (ptid_t ptid, void *buffer)
{
  haiku_nat_debug_printf ("ptid=%s, buffer=%p", ptid.to_string ().c_str (),
                          buffer);

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
  haiku_nat_debug_printf ("ptid=%s, buffer=%p", ptid.to_string ().c_str (),
                          buffer);

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
  haiku_nat_debug_printf ("ptid=%s, resume_kind=%i, sig=%i",
                          ptid.to_string ().c_str (), (int)kind, sig);

  std::unique_lock lock (team_debug_ports_lock);
  if (is_async_p ())
    pipe_to_worker.mark ();

  if (ptid == minus_one_ptid)
    {
      for (auto &[pid, context] : team_debug_contexts)
        {
          RETURN_AND_SET_ERRNO_IF_FAIL (context->resume (ptid, kind, sig));
          team_debug_ports.insert (context->debugger_port ());
        }
    }
  else
    {
      std::shared_ptr<team_debug_context> context;
      RETURN_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context));

      RETURN_AND_SET_ERRNO_IF_FAIL (context->resume (ptid, kind, sig));
      team_debug_ports.insert (context->debugger_port ());
    }

  return 0;
}

/* See haiku-nat.h.  */

ptid_t
wait (ptid_t ptid, struct target_waitstatus *ourstatus,
      target_wait_flags target_options)
{
  haiku_nat_debug_printf ("ptid=%s, target_options=%i",
                          ptid.to_string ().c_str (),
                          (int)target_options.raw ());

  gdb_assert (ourstatus != nullptr);

  if (is_async_p ())
    pipe_to_event_loop.flush ();

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

      haiku_nat_debug_printf ("chosen ptid=%s", ptid.to_string ().c_str ());
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
      haiku_nat_debug_printf ("removing deleted team context: team=%i",
                              chosen_context->team ());
      /* There's nothing left. Remove this team from our records.  */
      delete_context (chosen_context);
    }
  else
    {
      /* There might be more events on the ports.

         A false positive is harmless as long as GDB intends to call us again.
         We should not mark if the team is about to exit (and therefore stopped
         being waited by GDB). Otherwise, nothing will flush the event loop
         pipe, and GDB will enter an infinite loop.

         A false negative makes GDB hang forever.  */
      if (ptid != null_ptid && is_async_p ())
        {
          pipe_to_event_loop.mark ();

          team_debug_ports_lock.lock ();
          team_debug_ports.insert (chosen_context->debugger_port ());
          if (is_async_p ())
            pipe_to_worker.mark ();
          team_debug_ports_lock.unlock ();
        }
    }

  haiku_nat_debug_printf ("ptid=%s, ourstatus=%s", ptid.to_string ().c_str (),
                          ourstatus->to_string ().c_str ());

  return ptid;
}

/* See haiku-nat.h.  */

int
kill (pid_t pid)
{
  haiku_nat_debug_printf ("pid=%i", pid);

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
  haiku_nat_debug_printf ("pid=%i", pid);

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
  haiku_nat_debug_printf ("ptid=%s", ptid.to_string ().c_str ());

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
  haiku_nat_debug_printf ("pid=%i, memaddr=%p, myaddr=%p, size=%i", pid,
                          (void *)memaddr, myaddr, *sizeLeft);

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

  haiku_nat_debug_printf ("pid=%i, memaddr=%p success", pid, (void *)memaddr);

  return 0;
}

/* See haiku-nat.h.  */

int
write_memory (pid_t pid, CORE_ADDR memaddr, const unsigned char *myaddr,
              int *sizeLeft)
{
  haiku_nat_debug_printf ("pid=%i, memaddr=%p, myaddr=%p, size=%i", pid,
                          (void *)memaddr, myaddr, *sizeLeft);

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

  haiku_nat_debug_printf ("pid=%i, memaddr=%p success", pid, (void *)memaddr);

  return 0;
}

/* See haiku-nat.h.  */

int
read_offsets (pid_t pid, CORE_ADDR *text, CORE_ADDR *data)
{
  haiku_nat_debug_printf ("pid=%i", pid);

  CORE_ADDR raw_text;
  size_t raw_text_size;
  CORE_ADDR raw_data;

  std::shared_ptr<team_debug_context> context;
  if (get_context (pid, context) == B_OK && context->has_stored_app_image ())
    {
      haiku_nat_debug_printf ("reading offests from cached image");

      /* Prioritize the cached image. This might be useful right after an
         IMAGE_CREATED event, when we have all the information we need but the
         same info is not yet visible to get_next_image_info.  */
      raw_text = (CORE_ADDR)context->app_image ().text;
      raw_text_size = context->app_image ().text_size;
      raw_data = (CORE_ADDR)context->app_image ().data;
    }
  else
    {
      haiku_nat_debug_printf ("reading offests from system");

      if (for_each_image (
              pid,
              [&] (const image_info &info) {
                if (!info.is_main_executable)
                  return 0;

                raw_text = info.text;
                raw_text_size = info.text_size;
                raw_data = info.data;

                return 1;
              },
              true)
          < 0)
        return -1;
    }

  *text = raw_text;
  *data = raw_data - raw_text_size;
  return 0;
}

/* See haiku-nat.h.  */

bool
thread_stopped (ptid_t ptid)
{
  haiku_nat_debug_printf ("ptid=%s", ptid.to_string ().c_str ());

  std::shared_ptr<team_debug_context> context;
  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context),
                                      false);

  status_t status = context
                        ->send<B_DEBUG_MESSAGE_GET_CPU_STATE> (
                            { .thread = (thread_id)ptid.tid () })
                        .error;

  haiku_nat_debug_printf ("ptid=%s, status=%s", ptid.to_string ().c_str (),
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
  haiku_nat_debug_printf ("pid=%i", pid);

  std::shared_ptr<team_debug_context> context;
  if (get_context (pid, context) == B_OK && context->has_stored_app_image ())
    {
      return context->app_image ().name;
    }

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
  haiku_nat_debug_printf ("ptid=%s", ptid.to_string ().c_str ());

  static ::thread_info info;
  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (get_thread_info (ptid.tid (), &info),
                                      nullptr);

  haiku_nat_debug_printf ("ptid=%s, name=%s", ptid.to_string ().c_str (),
                          info.name);

  return info.name;
}

/* See haiku-nat.h.  */

std::string
pid_to_str (ptid_t ptid)
{
  haiku_nat_debug_printf ("ptid=%s", ptid.to_string ().c_str ());

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
  haiku_nat_debug_printf ("ptid=%s", ptid.to_string ().c_str ());

  std::shared_ptr<team_debug_context> context;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_context (ptid.pid (), context));

  RETURN_AND_SET_ERRNO_IF_FAIL (context->stop (ptid));

  return 0;
}

#define RETURN_OR_CONTINUE(exp)                                               \
  do                                                                          \
    {                                                                         \
      switch (exp)                                                            \
        {                                                                     \
        case -1:                                                              \
          return -1;                                                          \
        case 0:                                                               \
          continue;                                                           \
        case 1:                                                               \
          return 0;                                                           \
        }                                                                     \
    }                                                                         \
  while (0)

/* See haiku-nat.h  */

bool
is_async_p ()
{
  return async_worker_thread != -1;
}

/* See haiku-nat.h  */

int
async (bool enable)
{
  haiku_nat_debug_printf ("enable=%s", enable ? "true" : "false");

  /* TODO: We might want to share some code and infrastructure here with
     wait(). Ideally both should be backed by kernel-side event queues with
     all the debugger ports added.

     We can look at eliminating the worker thread all together in favor of
     accessing the private _kern_event_queue_create syscall and returning that
     FD as the async_wait_fd when Haiku finally adds support for polling event
     queue FDs. See https://dev.haiku-os.org/ticket/18954.  */

  if (enable == is_async_p ())
    return 0;

  if (!enable)
    {
      RETURN_AND_SET_ERRNO_IF_FAIL (
          send_signal (async_worker_thread, SIGKILLTHR));
      async_worker_thread = -1;
      pipe_to_worker.close_pipe ();
      pipe_to_event_loop.close_pipe ();
    }
  else
    {
      constexpr auto pipe_close
          = [] (event_pipe *pipe) { pipe->close_pipe (); };

      std::unique_ptr<event_pipe, decltype (pipe_close)>
          pipe_to_event_loop_closer (&pipe_to_event_loop, pipe_close);

      std::unique_ptr<event_pipe, decltype (pipe_close)>
          pipe_to_worker_closer (&pipe_to_event_loop, pipe_close);

      if (!pipe_to_event_loop.open_pipe ())
        return -1;

      if (!pipe_to_worker.open_pipe ())
        return -1;

      async_worker_thread = spawn_thread (
          [] (void *data) -> status_t {
            std::vector<object_wait_info> wait_infos;

            while (true)
              {
                wait_infos.clear ();
                wait_infos.emplace_back (
                    object_wait_info{ .object = pipe_to_worker.event_fd (),
                                      .type = B_OBJECT_TYPE_FD,
                                      .events = B_EVENT_READ });

                team_debug_ports_lock.lock ();
                for (port_id port : team_debug_ports)
                  {
                    wait_infos.emplace_back (
                        object_wait_info{ .object = port,
                                          .type = B_OBJECT_TYPE_PORT,
                                          .events = B_EVENT_READ });
                  }
                team_debug_ports_lock.unlock ();

                ssize_t ports_readable;

                do
                  {
                    ports_readable = wait_for_objects (wait_infos.data (),
                                                       wait_infos.size ());
                  }
                while (ports_readable == B_INTERRUPTED);

                gdb_assert (ports_readable > 0);

                if (wait_infos[0].events & B_EVENT_READ)
                  {
                    /* Woke up because a new team has been added.  */
                    --ports_readable;
                    pipe_to_worker.flush ();
                  }

                /* Remove dead ports.  */
                team_debug_ports_lock.lock ();
                for (size_t i = 1; i < wait_infos.size (); ++i)
                  {
                    const object_wait_info &wait_info = wait_infos[i];
                    if (wait_info.events & B_EVENT_INVALID)
                      {
                        team_debug_ports.erase (wait_info.object);
                        --ports_readable;
                      }
                    /* These events are one-shot. They will be re-added by
                       resume(). Otherwise, the worker thread loop would just
                       go on and on.  */
                    if (wait_info.events & B_EVENT_READ)
                      team_debug_ports.erase (wait_info.object);
                  }
                team_debug_ports_lock.unlock ();

                /* There are some events to read.  */
                if (ports_readable > 0)
                  pipe_to_event_loop.mark ();
              }
          },
          "gdb debugger port listener", B_NORMAL_PRIORITY, nullptr);

      if (async_worker_thread < 0)
        {
          errno = async_worker_thread;
          async_worker_thread = -1;
          return -1;
        }

      status_t status = resume_thread (async_worker_thread);
      if (status < B_OK)
        {
          send_signal (async_worker_thread, SIGKILLTHR);
          errno = status;
          async_worker_thread = -1;
          return -1;
        }

      /* Always trigger an initial event.  */
      pipe_to_event_loop.mark ();

      pipe_to_event_loop_closer.release ();
      pipe_to_worker_closer.release ();
    }

  return 0;
}

/* See haiku-nat.h  */

int
async_wait_fd ()
{
  return pipe_to_event_loop.event_fd ();
}

static void
convert_image_info (const ::image_info &haiku_info, image_info &info)
{
  info.id = haiku_info.id;
  info.text = (CORE_ADDR)haiku_info.text;
  info.text_size = (ULONGEST)haiku_info.text_size;
  info.data = (CORE_ADDR)haiku_info.data;
  info.data_size = (ULONGEST)haiku_info.data_size;
  info.name = haiku_info.name;
  info.sequence = haiku_info.sequence;
  info.init_order = haiku_info.init_order;
  info.is_main_executable = haiku_info.type == B_APP_IMAGE;
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
      convert_image_info (haiku_info, info);
      info.team = pid;

      RETURN_OR_CONTINUE (callback (info));
    }

  if (needs_one)
    {
      errno = B_ENTRY_NOT_FOUND;
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
      info.id = haiku_info.area;
      info.name = haiku_info.name;
      info.size = haiku_info.size;
      info.can_read = haiku_info.protection & B_READ_AREA;
      info.can_write = haiku_info.protection & B_WRITE_AREA;
      info.can_exec = haiku_info.protection & B_EXECUTE_AREA;
      info.is_stack = haiku_info.protection & B_STACK_AREA;
      info.can_clone = haiku_info.protection & B_CLONEABLE_AREA;
      info.team = haiku_info.team;
      info.ram_size = haiku_info.ram_size;
      info.copy_count = haiku_info.copy_count;
      info.in_count = haiku_info.in_count;
      info.out_count = haiku_info.out_count;
      info.address = (CORE_ADDR)haiku_info.address;

      RETURN_OR_CONTINUE (callback (info));
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
      info.team = haiku_info.team;
      info.name = haiku_info.name;

      RETURN_OR_CONTINUE (callback (info));
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_fd (pid_t pid,
             const std::function<int (const fd_info &info)> &callback)
{
  if (_kern_get_next_fd_info == nullptr)
    {
      haiku_nat_debug_printf ("Failed to issue get_next_fd_info syscall.");
      errno = ENOSYS;
      return -1;
    }

  static ::fd_info haiku_info;
  static fd_info info;
  static char path[B_PATH_NAME_LENGTH + 1];

  uint32 cookie = 0;

  while (
      _kern_get_next_fd_info (pid, &cookie, &haiku_info, sizeof (haiku_info))
      == B_OK)
    {
      info.number = haiku_info.number;
      info.device = haiku_info.device;
      info.node = haiku_info.node;
      info.team = pid;

      switch (haiku_info.open_mode & O_RWMASK)
        {
        case O_RDONLY:
          info.can_read = true;
          info.can_write = false;
          break;
        case O_WRONLY:
          info.can_read = false;
          info.can_write = true;
          break;
        case O_RDWR:
          info.can_read = true;
          info.can_write = true;
          break;
        }

      info.name = nullptr;

      if (_kern_entry_ref_to_path != nullptr)
        {
          /* This only works for directories.  */
          if (_kern_entry_ref_to_path (haiku_info.device, haiku_info.node,
                                       nullptr, path, B_PATH_NAME_LENGTH)
              >= B_OK)
            {
              path[B_PATH_NAME_LENGTH] = '\0';
              info.name = path;
            }
        }
      else
        {
          haiku_nat_debug_printf (
              "Failed to issue entry_ref_to_path syscall.");
        }

      RETURN_OR_CONTINUE (callback (info));
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_port (pid_t pid,
               const std::function<int (const port_info &info)> &callback)
{
  static ::port_info haiku_info;
  static port_info info;

  int32 cookie = 0;

  while (get_next_port_info (pid, &cookie, &haiku_info) == B_OK)
    {
      info.id = haiku_info.port;
      info.team = haiku_info.team;
      info.name = haiku_info.name;
      info.capacity = haiku_info.capacity;
      info.queue_count = haiku_info.queue_count;
      info.total_count = haiku_info.total_count;

      RETURN_OR_CONTINUE (callback (info));
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_sem (pid_t pid,
              const std::function<int (const sem_info &info)> &callback)
{
  static ::sem_info haiku_info;
  static sem_info info;

  int32 cookie = 0;

  while (get_next_sem_info (pid, &cookie, &haiku_info) == B_OK)
    {
      info.id = haiku_info.sem;
      info.team = haiku_info.team;
      info.name = haiku_info.name;
      info.count = haiku_info.count;
      info.latest_holder = haiku_info.latest_holder;

      RETURN_OR_CONTINUE (callback (info));
    }

  return 0;
}

static void
convert_team_info (const ::team_info &haiku_info, team_info &info)
{
  info.pid = haiku_info.team;
  info.args = haiku_info.args;
  info.thread_count = haiku_info.thread_count;
  info.image_count = haiku_info.image_count;
  info.area_count = haiku_info.area_count;
  info.debugger_nub_thread = haiku_info.debugger_nub_thread;
  info.debugger_nub_port = haiku_info.debugger_nub_port;
  info.uid = haiku_info.uid;
  info.gid = haiku_info.gid;
  info.real_uid = haiku_info.real_uid;
  info.real_gid = haiku_info.real_gid;
  info.group_id = haiku_info.group_id;
  info.session_id = haiku_info.session_id;
  info.parent = haiku_info.parent;
  info.name = haiku_info.name;
  info.start_time = haiku_info.start_time;
}

/* See haiku-nat.h.  */

const team_info *
get_team (pid_t pid)
{
  static ::team_info haiku_info;
  static team_info info;

  RETURN_VALUE_AND_SET_ERRNO_IF_FAIL (get_team_info (pid, &haiku_info),
                                      nullptr);

  convert_team_info (haiku_info, info);

  return &info;
}

/* See haiku-nat.h.  */

int
for_each_team (const std::function<int (const team_info &info)> &callback)
{
  static ::team_info haiku_info;
  static team_info info;

  int32 cookie = 0;

  while (get_next_team_info (&cookie, &haiku_info) == B_OK)
    {
      convert_team_info (haiku_info, info);

      RETURN_OR_CONTINUE (callback (info));
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_commpage_symbol (
    const std::function<int (const commpage_symbol_info &info)> &callback)
{
  if (_kern_read_kernel_image_symbols == nullptr)
    {
      haiku_nat_debug_printf (
          "Failed to issue read_kernel_image_symbols syscall.");
      errno = ENOSYS;
      return -1;
    }

  image_id commpage_image = -1;
  if (for_each_image (
          B_SYSTEM_TEAM,
          [&] (const image_info &image_info) {
            if (strcmp (image_info.name, "commpage") == 0)
              {
                commpage_image = image_info.id;
                return 1;
              }
            return 0;
          },
          true)
      < 0)
    {
      return -1;
    }

  int32 symbol_count = 0;
  size_t string_table_size = 0;
  RETURN_AND_SET_ERRNO_IF_FAIL (
      _kern_read_kernel_image_symbols (commpage_image, nullptr, &symbol_count,
                                       nullptr, &string_table_size, nullptr));

  std::vector<elf_sym> symbols (symbol_count);
  /* An additional guaranteed null terminator.  */
  std::vector<char> string_table (string_table_size + 1);

  RETURN_AND_SET_ERRNO_IF_FAIL (_kern_read_kernel_image_symbols (
      commpage_image, symbols.data (), &symbol_count, string_table.data (),
      &string_table_size, nullptr));

  if (symbols.size () > symbol_count)
    symbols.resize (symbol_count);

  string_table.back () = '\0';

  static commpage_symbol_info info;

  for (const auto &sym : symbols)
    {
      info.name = string_table.data () + sym.st_name;
      info.value = sym.st_value;
      info.size = sym.st_size;
      info.is_function = ELF_ST_TYPE (sym.st_info) == STT_FUNC;
      info.is_object = ELF_ST_TYPE (sym.st_info) == STT_OBJECT;

      RETURN_OR_CONTINUE (callback (info));
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_cpu (const std::function<int (const cpu_info &info)> &callback)
{
  system_info sysinfo;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_system_info (&sysinfo));

  size_t cpu_count = sysinfo.cpu_count;

  std::vector< ::cpu_info> haiku_cpu_infos (cpu_count);
  RETURN_AND_SET_ERRNO_IF_FAIL (
      get_cpu_info (0, cpu_count, haiku_cpu_infos.data ()));

  uint32 node_count = 0;
  RETURN_AND_SET_ERRNO_IF_FAIL (get_cpu_topology_info (nullptr, &node_count));

  std::vector< ::cpu_topology_node_info> haiku_cpu_nodes (node_count);
  RETURN_AND_SET_ERRNO_IF_FAIL (
      get_cpu_topology_info (haiku_cpu_nodes.data (), &node_count));

  if (haiku_cpu_nodes.size () > node_count)
    haiku_cpu_nodes.resize (node_count);

  static cpu_info info;

  for (const auto &node : haiku_cpu_nodes)
    {
      switch (node.type)
        {
        case B_TOPOLOGY_ROOT:
          switch (node.data.root.platform)
            {
            case B_CPU_x86:
              info.platform = "BePC";
              break;
            case B_CPU_x86_64:
              info.platform = "x86_64";
              break;
            case B_CPU_PPC:
              info.platform = "ppc";
              break;
            case B_CPU_PPC_64:
              info.platform = "ppc64";
              break;
            case B_CPU_M68K:
              info.platform = "m68k";
              break;
            case B_CPU_ARM:
              info.platform = "arm";
              break;
            case B_CPU_ARM_64:
              info.platform = "aarch64";
              break;
            case B_CPU_RISC_V:
              info.platform = "riscv64";
              break;
            case B_CPU_UNKNOWN:
            default:
              info.platform = "unknown";
              break;
            }
          break;
        case B_TOPOLOGY_PACKAGE:
          switch (node.data.package.vendor)
            {
            case B_CPU_VENDOR_AMD:
              info.vendor = "AMD";
              break;
            case B_CPU_VENDOR_INTEL:
              info.vendor = "Intel";
              break;
            case B_CPU_UNKNOWN:
            default:
              info.vendor = "Unknown";
            }
          info.cache_line_size = node.data.package.cache_line_size;
          break;
        case B_TOPOLOGY_CORE:
          info.model = node.data.core.model;
          info.default_frequency = node.data.core.default_frequency;
          break;
        case B_TOPOLOGY_SMT:
          {
            /* The leaf node, corresponding to exactly one core.  */
            const ::cpu_info &haiku_info = haiku_cpu_infos.at (node.id);

            info.id = node.id;
            info.current_frequency = haiku_info.current_frequency;
            info.active_time = haiku_info.active_time;
            info.enabled = haiku_info.enabled;

            RETURN_OR_CONTINUE (callback (info));
          }
          break;
        }
    }

  return 0;
}

/* See haiku-nat.h.  */

int
for_each_socket (const std::function<int (const socket_info &info)> &callback)
{
  if (_kern_get_next_socket_stat == nullptr)
    {
      haiku_nat_debug_printf ("Failed to issue get_next_socket_stat syscall.");
      errno = ENOSYS;
      return -1;
    }

  static net_stat haiku_info;
  static socket_info info;

  std::string family_str;
  std::string type_str;
  std::string address_str;
  std::string peer_str;

  uint32 cookie = 0;
  while (_kern_get_next_socket_stat (-1, &cookie, &haiku_info) == B_OK)
    {
      switch (haiku_info.family)
        {
        case AF_UNIX:
          {
            family_str = "unix";

            const sockaddr_un *address = (sockaddr_un *)&haiku_info.address;
            address_str = address->sun_path;

            const sockaddr_un *peer = (sockaddr_un *)&haiku_info.peer;
            peer_str = peer->sun_path;
          }
          break;
        case AF_INET:
          {
            family_str = "inet";

            static const auto format_address = [] (const sockaddr_in *addr) {
              std::string result;

              if (addr->sin_addr.s_addr == INADDR_ANY)
                result = "*";
              else
                result = inet_ntoa (addr->sin_addr);

              result += ":";

              if (addr->sin_port == 0)
                result += "*";
              else
                result += std::to_string (ntohs (addr->sin_port));

              return result;
            };

            address_str = format_address ((sockaddr_in *)&haiku_info.address);
            peer_str = format_address ((sockaddr_in *)&haiku_info.peer);
          }
          break;
        case AF_INET6:
          family_str = "inet6";

          static const auto format_address = [] (const sockaddr_in6 *addr) {
            std::string result;

            static char buffer[INET6_ADDRSTRLEN];

            if (memcmp (&addr->sin6_addr, &in6addr_any, sizeof (in6_addr))
                == 0)
              result = "*";
            else
              result = inet_ntop (AF_INET6, &addr->sin6_addr, buffer,
                                  sizeof (buffer));

            result = "[" + result + "]:";

            if (addr->sin6_port == 0)
              result += "*";
            else
              result += std::to_string (ntohs (addr->sin6_port));

            return result;
          };

          address_str = format_address ((sockaddr_in6 *)&haiku_info.address);
          peer_str = format_address ((sockaddr_in6 *)&haiku_info.peer);

          break;
        default:
          family_str = std::to_string (haiku_info.family);
          address_str = peer_str = "-";
          break;
        }

      switch (haiku_info.type)
        {
        case SOCK_STREAM:
          switch (haiku_info.family)
            {
            case AF_INET:
            case AF_INET6:
              type_str = "tcp";
              break;
            default:
              type_str = "stream";
            }
          break;
        case SOCK_DGRAM:
          switch (haiku_info.family)
            {
            case AF_INET:
            case AF_INET6:
              type_str = "udp";
              break;
            default:
              type_str = "dgram";
            }
          break;
        case SOCK_RAW:
          type_str = "raw";
          break;
        case SOCK_SEQPACKET:
          type_str = "seqpacket";
          break;
        case SOCK_MISC:
          type_str = "misc";
          break;
        }

      info.family = family_str.c_str ();
      info.type = type_str.c_str ();
      info.state = haiku_info.state;
      info.team = haiku_info.owner;
      info.address = address_str.c_str ();
      info.peer = peer_str.c_str ();
      info.receive_queue_size = haiku_info.receive_queue_size;
      info.send_queue_size = haiku_info.send_queue_size;

      RETURN_OR_CONTINUE (callback (info));
    }

  return 0;
}

}
