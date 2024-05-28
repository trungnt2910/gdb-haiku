/* Haiku-specific functions to retrieve OS data.

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

#include "gdbsupport/common-defs.h"
#include "gdbsupport/xml-utils.h"

#include "diagnostics.h"

#include "nat/haiku-nat.h"
#include "nat/haiku-osdata.h"

using namespace haiku_nat;

template <typename InfoT>
int
all_teams (int (*for_each) (pid_t, const std::function<int (const InfoT &)> &),
           const std::function<int (const InfoT &)> &callback)
{
  return for_each_team (
      [&] (const team_info &info) { return for_each (info.pid, callback); });
}

static int
for_each_image (pid_t pid,
                const std::function<int (const image_info &info)> &callback)
{
  return for_each_image (pid, callback, false);
}

static struct osdata_type
{
  const char *type;
  const char *title;
  const char *description;
  std::string (*take_snapshot) ();
  std::string buffer;
} osdata_table[] = {
  {
      .type = "types",
      .title = "Types",
      .description = "Listing of info os types you can list",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"types\">\n";

        /* Start the below loop at 1, as we do not want to list
           ourselves.  */
        for (int i = 1; osdata_table[i].type; ++i)
          string_xml_appendf (buffer,
                              "<item>"
                              "<column name=\"Type\">%s</column>"
                              "<column name=\"Description\">%s</column>"
                              "<column name=\"Title\">%s</column>"
                              "</item>",
                              osdata_table[i].type,
                              osdata_table[i].description,
                              osdata_table[i].title);

        buffer += "</osdata>\n";

        return buffer;
      },
  },
  {
      .type = "areas",
      .title = "Areas",
      .description = "Listing of all areas",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"areas\">\n";

        all_teams<area_info> (for_each_area, [&] (const area_info &info) {
          std::string prot;
          if (info.can_read)
            prot += "r";
          if (info.can_write)
            prot += "w";
          if (info.can_exec)
            prot += "x";
          if (info.is_stack)
            prot += "s";
          if (info.can_clone)
            prot += "c";

          string_xml_appendf (
              buffer,
              "<item>"
              "<column name=\"team\">%s</column>"
              "<column name=\"id\">%s</column>"
              "<column name=\"name\">%s</column>"
              "<column name=\"address\">%s</column>"
              "<column name=\"size\">%s</column>"
              "<column name=\"prot\">%s</column>"
              "<column name=\"ram\">%s</column>"
              "<column name=\"#-cow\">%s</column>"
              "<column name=\"#-in\">%s</column>"
              "<column name=\"#-out\">%s</column>"
              "</item>",
              plongest (info.team), plongest (info.id), info.name,
              core_addr_to_string (info.address), pulongest (info.size),
              prot.c_str (), pulongest (info.ram_size),
              pulongest (info.copy_count), pulongest (info.in_count),
              pulongest (info.out_count));

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "comm",
      .title = "Commpage symbols",
      .description = "Listing of all symbols on the system commpage",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"comm\">\n";

        for_each_commpage_symbol ([&] (const commpage_symbol_info &info) {
          std::string type;
          if (info.is_function)
            type += "f";
          if (info.is_object)
            type += "o";

          /* BE CAREFUL WHAT WE RETURN HERE!
             This operation is used mainly by haiku-tdep.c to synthesize the
             commpage object. Changing the format might break GDB itself. */
          string_xml_appendf (buffer,
                              "<item>"
                              "<column name=\"name\">%s</column>"
                              "<column name=\"value\">%s</column>"
                              "<column name=\"size\">%s</column>"
                              "<column name=\"type\">%s</column>"
                              "</item>",
                              info.name, pulongest (info.value),
                              pulongest (info.size), type.c_str ());

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "cpus",
      .title = "CPUs",
      .description = "Listing of all CPUs/cores on the system",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"cpus\">\n";

        for_each_cpu ([&] (const cpu_info &info) {
          string_xml_appendf (
              buffer,
              "<item>"
              "<column name=\"id\">%s</column>"
              "<column name=\"platform\">%s</column>"
              "<column name=\"vendor\">%s</column>"
              "<column name=\"cache\">%s</column>"
              "<column name=\"model\">%s</column>"
              "<column name=\"default freq.\">%s</column>"
              "<column name=\"current freq.\">%s</column>"
              "<column name=\"active time\">%s</column>"
              "<column name=\"enabled\">%s</column>"
              "</item>",
              plongest (info.id), info.platform, info.vendor,
              pulongest (info.cache_line_size), pulongest (info.model),
              pulongest (info.default_frequency),
              pulongest (info.current_frequency), pulongest (info.active_time),
              info.enabled ? "true" : "false");

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "files",
      .title = "File descriptors",
      .description = "Listing of all file descriptors",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"files\">\n";

        all_teams<fd_info> (for_each_fd, [&] (const fd_info &info) {
          std::string mode;
          if (info.can_read)
            mode += "r";
          if (info.can_write)
            mode += "w";

          string_xml_appendf (
              buffer,
              "<item>"
              "<column name=\"team\">%s</column>"
              "<column name=\"file descriptor\">%s</column>"
              "<column name=\"mode\">%s</column>"
              "<column name=\"device\">%s</column>"
              "<column name=\"node\">%s</column>"
              "<column name=\"name\">%s</column>"
              "</item>",
              plongest (info.team), plongest (info.number), mode.c_str (),
              plongest (info.device), plongest (info.node),
              (info.name != nullptr) ? info.name : "(unknown)");

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "images",
      .title = "Images",
      .description = "Listing of all images",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"images\">\n";

        all_teams<image_info> (for_each_image, [&] (const image_info &info) {
          string_xml_appendf (
              buffer,
              "<item>"
              "<column name=\"team\">%s</column>"
              "<column name=\"id\">%s</column>"
              "<column name=\"text\">%s</column>"
              "<column name=\"data\">%s</column>"
              "<column name=\"seq#\">%s</column>"
              "<column name=\"init#\">%s</column>"
              "<column name=\"name\">%s</column>"
              "</item>",
              plongest (info.team), plongest (info.id),
              core_addr_to_string (info.text), core_addr_to_string (info.data),
              plongest (info.sequence), plongest (info.init_order), info.name);

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "ports",
      .title = "Ports",
      .description = "Listing of all ports",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"ports\">\n";

        all_teams<port_info> (for_each_port, [&] (const port_info &info) {
          string_xml_appendf (buffer,
                              "<item>"
                              "<column name=\"team\">%s</column>"
                              "<column name=\"id\">%s</column>"
                              "<column name=\"name\">%s</column>"
                              "<column name=\"capacity\">%s</column>"
                              "<column name=\"queued\">%s</column>"
                              "<column name=\"total\">%s</column>"
                              "</item>",
                              plongest (info.team), plongest (info.id),
                              info.name, plongest (info.capacity),
                              plongest (info.queue_count),
                              plongest (info.total_count));

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "sems",
      .title = "Semaphores",
      .description = "Listing of all semaphores",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"sems\">\n";

        all_teams<sem_info> (for_each_sem, [&] (const sem_info &info) {
          string_xml_appendf (buffer,
                              "<item>"
                              "<column name=\"team\">%s</column>"
                              "<column name=\"id\">%s</column>"
                              "<column name=\"name\">%s</column>"
                              "<column name=\"count\">%s</column>"
                              "<column name=\"holder\">%s</column>"
                              "</item>",
                              plongest (info.team), plongest (info.id),
                              info.name, plongest (info.count),
                              plongest (info.latest_holder));

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "sockets",
      .title = "Sockets",
      .description = "Listing of all sockets",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"sockets\">\n";

        for_each_socket ([&] (const socket_info &info) {
          string_xml_appendf (buffer,
                              "<item>"
                              "<column name=\"team\">%s</column>"
                              "<column name=\"family\">%s</column>"
                              "<column name=\"protocol\">%s</column>"
                              "<column name=\"local address\">%s</column>"
                              "<column name=\"remote address\">%s</column>"
                              "<column name=\"state\">%s</column>"
                              "<column name=\"recv-q\">%s</column>"
                              "<column name=\"send-q\">%s</column>"
                              "</item>",
                              plongest (info.team), info.family, info.type,
                              info.address, info.peer, info.state,
                              pulongest (info.receive_queue_size),
                              pulongest (info.send_queue_size));

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "teams",
      .title = "Teams",
      .description = "Listing of all teams",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"teams\">\n";

        for_each_team ([&] (const team_info &info) {
          string_xml_appendf (buffer,
                              "<item>"
                              "<column name=\"id\">%s</column>"
                              "<column name=\"uid\">%s</column>"
                              "<column name=\"command\">%s</column>"
                              "</item>",
                              pulongest (info.pid), pulongest (info.uid),
                              info.args);

          return 0;
        });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  {
      .type = "threads",
      .title = "Threads",
      .description = "Listing of all threads",
      .take_snapshot = [] () -> std::string {
        std::string buffer = "<osdata type=\"threads\">\n";

        all_teams<thread_info> (
            for_each_thread, [&] (const thread_info &info) {
              string_xml_appendf (buffer,
                                  "<item>"
                                  "<column name=\"team\">%s</column>"
                                  "<column name=\"id\">%s</column>"
                                  "<column name=\"name\">%s</column>"
                                  "</item>",
                                  plongest (info.team), plongest (info.tid),
                                  info.name);

              return 0;
            });

        buffer += "</osdata>\n";
        return buffer;
      },
  },
  /* TODO: There are also private syscalls for disk info,
     but let's just ignore them for now.  */
  { NULL }
};

/*  Copies up to LEN bytes in READBUF from offset OFFSET in OSD->BUFFER.
    If OFFSET is zero, first calls OSD->TAKE_SNAPSHOT.  */

static LONGEST
common_getter (struct osdata_type *osd, gdb_byte *readbuf, ULONGEST offset,
               ULONGEST len)
{
  gdb_assert (readbuf);

  if (offset == 0)
    osd->buffer = osd->take_snapshot ();

  if (offset >= osd->buffer.size ())
    {
      /* Done.  Get rid of the buffer.  */
      osd->buffer.clear ();
      return 0;
    }

  len = std::min (len, osd->buffer.size () - offset);
  memcpy (readbuf, &osd->buffer[offset], len);

  return len;
}

LONGEST
haiku_common_xfer_osdata (const char *annex, gdb_byte *readbuf,
                          ULONGEST offset, ULONGEST len)
{
  if (!annex || *annex == '\0')
    {
      return common_getter (&osdata_table[0], readbuf, offset, len);
    }
  else
    {
      int i;

      for (i = 0; osdata_table[i].type; ++i)
        {
          if (strcmp (annex, osdata_table[i].type) == 0)
            return common_getter (&osdata_table[i], readbuf, offset, len);
        }

      return 0;
    }
}
