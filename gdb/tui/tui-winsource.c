/* TUI display source/assembly window.

   Copyright 1998, 1999, 2000, 2001, 2002, 2003, 2004 Free Software
   Foundation, Inc.

   Contributed by Hewlett-Packard Company.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "defs.h"
#include <ctype.h>
#include "symtab.h"
#include "frame.h"
#include "breakpoint.h"
#include "value.h"
#include "source.h"

#include "tui/tui.h"
#include "tui/tui-data.h"
#include "tui/tui-stack.h"
#include "tui/tui-win.h"
#include "tui/tui-wingeneral.h"
#include "tui/tui-winsource.h"
#include "tui/tui-source.h"
#include "tui/tui-disasm.h"

#ifdef HAVE_NCURSES_H       
#include <ncurses.h>
#else
#ifdef HAVE_CURSES_H
#include <curses.h>
#endif
#endif

/* Function to display the "main" routine.  */
void
tui_display_main (void)
{
  if ((tui_source_windows ())->count > 0)
    {
      CORE_ADDR addr;

      addr = tui_get_begin_asm_address ();
      if (addr != (CORE_ADDR) 0)
	{
	  struct symtab_and_line sal;

	  tui_update_source_windows_with_addr (addr);
	  sal = find_pc_line (addr, 0);
          if (sal.symtab)
             tui_update_locator_filename (sal.symtab->filename);
          else
             tui_update_locator_filename ("??");
	}
    }
}



/* Function to display source in the source window.  This function
   initializes the horizontal scroll to 0.  */
void
tui_update_source_window (struct tui_win_info * winInfo, struct symtab *s,
			  union tui_line_or_address lineOrAddr, int noerror)
{
  winInfo->detail.sourceInfo.horizontalOffset = 0;
  tui_update_source_window_as_is (winInfo, s, lineOrAddr, noerror);

  return;
}


/* Function to display source in the source/asm window.  This function
   shows the source as specified by the horizontal offset.  */
void
tui_update_source_window_as_is (struct tui_win_info * winInfo, struct symtab *s,
				union tui_line_or_address lineOrAddr, int noerror)
{
  enum tui_status ret;

  if (winInfo->generic.type == SRC_WIN)
    ret = tui_set_source_content (s, lineOrAddr.lineNo, noerror);
  else
    ret = tui_set_disassem_content (lineOrAddr.addr);

  if (ret == TUI_FAILURE)
    {
      tui_clear_source_content (winInfo, EMPTY_SOURCE_PROMPT);
      tui_clear_exec_info_content (winInfo);
    }
  else
    {
      tui_update_breakpoint_info (winInfo, 0);
      tui_show_source_content (winInfo);
      tui_update_exec_info (winInfo);
      if (winInfo->generic.type == SRC_WIN)
	{
	  struct symtab_and_line sal;
	  
	  sal.line = lineOrAddr.lineNo +
	    (winInfo->generic.contentSize - 2);
	  sal.symtab = s;
	  set_current_source_symtab_and_line (&sal);
	  /*
	     ** If the focus was in the asm win, put it in the src
	     ** win if we don't have a split layout
	   */
	  if (tui_win_with_focus () == disassemWin &&
	      tui_current_layout () != SRC_DISASSEM_COMMAND)
	    tui_set_win_focus_to (srcWin);
	}
    }


  return;
}


/* Function to ensure that the source and/or disassemly windows
   reflect the input address.  */
void
tui_update_source_windows_with_addr (CORE_ADDR addr)
{
  if (addr != 0)
    {
      struct symtab_and_line sal;
      union tui_line_or_address l;
      
      switch (tui_current_layout ())
	{
	case DISASSEM_COMMAND:
	case DISASSEM_DATA_COMMAND:
	  tui_show_disassem (addr);
	  break;
	case SRC_DISASSEM_COMMAND:
	  tui_show_disassem_and_update_source (addr);
	  break;
	default:
	  sal = find_pc_line (addr, 0);
	  l.lineNo = sal.line;
	  tui_show_symtab_source (sal.symtab, l, FALSE);
	  break;
	}
    }
  else
    {
      int i;

      for (i = 0; i < (tui_source_windows ())->count; i++)
	{
	  struct tui_win_info * winInfo = (struct tui_win_info *) (tui_source_windows ())->list[i];

	  tui_clear_source_content (winInfo, EMPTY_SOURCE_PROMPT);
	  tui_clear_exec_info_content (winInfo);
	}
    }

  return;
}				/* tuiUpdateSourceWindowsWithAddr */

/* Function to ensure that the source and/or disassemly windows
   reflect the input address.  */
void
tui_update_source_windows_with_line (struct symtab *s, int line)
{
  CORE_ADDR pc;
  union tui_line_or_address l;
  
  switch (tui_current_layout ())
    {
    case DISASSEM_COMMAND:
    case DISASSEM_DATA_COMMAND:
      find_line_pc (s, line, &pc);
      tui_update_source_windows_with_addr (pc);
      break;
    default:
      l.lineNo = line;
      tui_show_symtab_source (s, l, FALSE);
      if (tui_current_layout () == SRC_DISASSEM_COMMAND)
	{
	  find_line_pc (s, line, &pc);
	  tui_show_disassem (pc);
	}
      break;
    }

  return;
}

void
tui_clear_source_content (struct tui_win_info * winInfo, int displayPrompt)
{
  if (m_winPtrNotNull (winInfo))
    {
      register int i;

      winInfo->generic.contentInUse = FALSE;
      tui_erase_source_content (winInfo, displayPrompt);
      for (i = 0; i < winInfo->generic.contentSize; i++)
	{
	  struct tui_win_element * element =
	  (struct tui_win_element *) winInfo->generic.content[i];
	  element->whichElement.source.hasBreak = FALSE;
	  element->whichElement.source.isExecPoint = FALSE;
	}
    }

  return;
}				/* tuiClearSourceContent */


void
tui_erase_source_content (struct tui_win_info * winInfo, int displayPrompt)
{
  int xPos;
  int halfWidth = (winInfo->generic.width - 2) / 2;

  if (winInfo->generic.handle != (WINDOW *) NULL)
    {
      werase (winInfo->generic.handle);
      tui_check_and_display_highlight_if_needed (winInfo);
      if (displayPrompt == EMPTY_SOURCE_PROMPT)
	{
	  char *noSrcStr;

	  if (winInfo->generic.type == SRC_WIN)
	    noSrcStr = NO_SRC_STRING;
	  else
	    noSrcStr = NO_DISASSEM_STRING;
	  if (strlen (noSrcStr) >= halfWidth)
	    xPos = 1;
	  else
	    xPos = halfWidth - strlen (noSrcStr);
	  mvwaddstr (winInfo->generic.handle,
		     (winInfo->generic.height / 2),
		     xPos,
		     noSrcStr);

	  /* elz: added this function call to set the real contents of
	     the window to what is on the  screen, so that later calls
	     to refresh, do display
	     the correct stuff, and not the old image */

	  tui_set_source_content_nil (winInfo, noSrcStr);
	}
      tui_refresh_win (&winInfo->generic);
    }
  return;
}				/* tuiEraseSourceContent */


/* Redraw the complete line of a source or disassembly window.  */
static void
tui_show_source_line (struct tui_win_info * winInfo, int lineno)
{
  struct tui_win_element * line;
  int x, y;

  line = (struct tui_win_element *) winInfo->generic.content[lineno - 1];
  if (line->whichElement.source.isExecPoint)
    wattron (winInfo->generic.handle, A_STANDOUT);

  mvwaddstr (winInfo->generic.handle, lineno, 1,
             line->whichElement.source.line);
  if (line->whichElement.source.isExecPoint)
    wattroff (winInfo->generic.handle, A_STANDOUT);

  /* Clear to end of line but stop before the border.  */
  getyx (winInfo->generic.handle, y, x);
  while (x + 1 < winInfo->generic.width)
    {
      waddch (winInfo->generic.handle, ' ');
      getyx (winInfo->generic.handle, y, x);
    }
}

void
tui_show_source_content (struct tui_win_info * winInfo)
{
  if (winInfo->generic.contentSize > 0)
    {
      int lineno;

      for (lineno = 1; lineno <= winInfo->generic.contentSize; lineno++)
        tui_show_source_line (winInfo, lineno);
    }
  else
    tui_erase_source_content (winInfo, TRUE);

  tui_check_and_display_highlight_if_needed (winInfo);
  tui_refresh_win (&winInfo->generic);
  winInfo->generic.contentInUse = TRUE;
}


/* Scroll the source forward or backward horizontally.  */
void
tui_horizontal_source_scroll (struct tui_win_info * winInfo,
			      enum tui_scroll_direction direction,
			      int numToScroll)
{
  if (winInfo->generic.content != NULL)
    {
      int offset;
      struct symtab *s;
      struct symtab_and_line cursal = get_current_source_symtab_and_line ();

      if (cursal.symtab == (struct symtab *) NULL)
	s = find_pc_symtab (get_frame_pc (deprecated_selected_frame));
      else
	s = cursal.symtab;

      if (direction == LEFT_SCROLL)
	offset = winInfo->detail.sourceInfo.horizontalOffset + numToScroll;
      else
	{
	  if ((offset =
	     winInfo->detail.sourceInfo.horizontalOffset - numToScroll) < 0)
	    offset = 0;
	}
      winInfo->detail.sourceInfo.horizontalOffset = offset;
      tui_update_source_window_as_is (winInfo, s,
				      ((struct tui_win_element *)
				       winInfo->generic.content[0])->whichElement.source.lineOrAddr,
				      FALSE);
    }

  return;
}				/* tuiHorizontalSourceScroll */


/* Set or clear the hasBreak flag in the line whose line is lineNo.  */
void
tui_set_is_exec_point_at (union tui_line_or_address l, struct tui_win_info * winInfo)
{
  int changed = 0;
  int i;
  tui_win_content content = (tui_win_content) winInfo->generic.content;

  i = 0;
  while (i < winInfo->generic.contentSize)
    {
      int newState;

      if (content[i]->whichElement.source.lineOrAddr.addr == l.addr)
        newState = TRUE;
      else
	newState = FALSE;
      if (newState != content[i]->whichElement.source.isExecPoint)
        {
          changed++;
          content[i]->whichElement.source.isExecPoint = newState;
          tui_show_source_line (winInfo, i + 1);
        }
      i++;
    }
  if (changed)
    tui_refresh_win (&winInfo->generic);
}

/* Update the execution windows to show the active breakpoints.
   This is called whenever a breakpoint is inserted, removed or
   has its state changed.  */
void
tui_update_all_breakpoint_info ()
{
  struct tui_list *list = tui_source_windows ();
  int i;

  for (i = 0; i < list->count; i++)
    {
      struct tui_win_info * win = (struct tui_win_info *) list->list[i];

      if (tui_update_breakpoint_info (win, FALSE))
        {
          tui_update_exec_info (win);
        }
    }
}


/* Scan the source window and the breakpoints to update the
   hasBreak information for each line.
   Returns 1 if something changed and the execution window
   must be refreshed.  */
int
tui_update_breakpoint_info (struct tui_win_info * win, int current_only)
{
  int i;
  int need_refresh = 0;
  struct tui_source_info * src = &win->detail.sourceInfo;

  for (i = 0; i < win->generic.contentSize; i++)
    {
      struct breakpoint *bp;
      extern struct breakpoint *breakpoint_chain;
      int mode;
      struct tui_source_element* line;

      line = &((struct tui_win_element *) win->generic.content[i])->whichElement.source;
      if (current_only && !line->isExecPoint)
         continue;

      /* Scan each breakpoint to see if the current line has something to
         do with it.  Identify enable/disabled breakpoints as well as
         those that we already hit.  */
      mode = 0;
      for (bp = breakpoint_chain;
           bp != (struct breakpoint *) NULL;
           bp = bp->next)
        {
          if ((win == srcWin
               && bp->source_file
               && (strcmp (src->filename, bp->source_file) == 0)
               && bp->line_number == line->lineOrAddr.lineNo)
              || (win == disassemWin
                  && bp->loc->address == line->lineOrAddr.addr))
            {
              if (bp->enable_state == bp_disabled)
                mode |= TUI_BP_DISABLED;
              else
                mode |= TUI_BP_ENABLED;
              if (bp->hit_count)
                mode |= TUI_BP_HIT;
              if (bp->cond)
                mode |= TUI_BP_CONDITIONAL;
              if (bp->type == bp_hardware_breakpoint)
                mode |= TUI_BP_HARDWARE;
            }
        }
      if (line->hasBreak != mode)
        {
          line->hasBreak = mode;
          need_refresh = 1;
        }
    }
  return need_refresh;
}


/*
   ** tuiSetExecInfoContent().
   **      Function to initialize the content of the execution info window,
   **      based upon the input window which is either the source or
   **      disassembly window.
 */
enum tui_status
tuiSetExecInfoContent (struct tui_win_info * winInfo)
{
  enum tui_status ret = TUI_SUCCESS;

  if (winInfo->detail.sourceInfo.executionInfo != (struct tui_gen_win_info *) NULL)
    {
      struct tui_gen_win_info * execInfoPtr = winInfo->detail.sourceInfo.executionInfo;

      if (execInfoPtr->content == NULL)
	execInfoPtr->content =
	  (void **) tui_alloc_content (winInfo->generic.height,
					 execInfoPtr->type);
      if (execInfoPtr->content != NULL)
	{
	  int i;

          tui_update_breakpoint_info (winInfo, 1);
	  for (i = 0; i < winInfo->generic.contentSize; i++)
	    {
	      struct tui_win_element * element;
	      struct tui_win_element * srcElement;
              int mode;

	      element = (struct tui_win_element *) execInfoPtr->content[i];
	      srcElement = (struct tui_win_element *) winInfo->generic.content[i];

              memset(element->whichElement.simpleString, ' ',
                     sizeof(element->whichElement.simpleString));
              element->whichElement.simpleString[TUI_EXECINFO_SIZE - 1] = 0;

	      /* Now update the exec info content based upon the state
                 of each line as indicated by the source content.  */
              mode = srcElement->whichElement.source.hasBreak;
              if (mode & TUI_BP_HIT)
                element->whichElement.simpleString[TUI_BP_HIT_POS] =
                  (mode & TUI_BP_HARDWARE) ? 'H' : 'B';
              else if (mode & (TUI_BP_ENABLED | TUI_BP_DISABLED))
                element->whichElement.simpleString[TUI_BP_HIT_POS] =
                  (mode & TUI_BP_HARDWARE) ? 'h' : 'b';

              if (mode & TUI_BP_ENABLED)
                element->whichElement.simpleString[TUI_BP_BREAK_POS] = '+';
              else if (mode & TUI_BP_DISABLED)
                element->whichElement.simpleString[TUI_BP_BREAK_POS] = '-';

              if (srcElement->whichElement.source.isExecPoint)
                element->whichElement.simpleString[TUI_EXEC_POS] = '>';
	    }
	  execInfoPtr->contentSize = winInfo->generic.contentSize;
	}
      else
	ret = TUI_FAILURE;
    }

  return ret;
}


/*
   ** tuiShowExecInfoContent().
 */
void
tuiShowExecInfoContent (struct tui_win_info * winInfo)
{
  struct tui_gen_win_info * execInfo = winInfo->detail.sourceInfo.executionInfo;
  int curLine;

  werase (execInfo->handle);
  tui_refresh_win (execInfo);
  for (curLine = 1; (curLine <= execInfo->contentSize); curLine++)
    mvwaddstr (execInfo->handle,
	       curLine,
	       0,
	       ((struct tui_win_element *)
		execInfo->content[curLine - 1])->whichElement.simpleString);
  tui_refresh_win (execInfo);
  execInfo->contentInUse = TRUE;

  return;
}


void
tui_erase_exec_info_content (struct tui_win_info * winInfo)
{
  struct tui_gen_win_info * execInfo = winInfo->detail.sourceInfo.executionInfo;

  werase (execInfo->handle);
  tui_refresh_win (execInfo);

  return;
}

void
tui_clear_exec_info_content (struct tui_win_info * winInfo)
{
  winInfo->detail.sourceInfo.executionInfo->contentInUse = FALSE;
  tui_erase_exec_info_content (winInfo);

  return;
}

/* Function to update the execution info window.  */
void
tui_update_exec_info (struct tui_win_info * winInfo)
{
  tuiSetExecInfoContent (winInfo);
  tuiShowExecInfoContent (winInfo);
}				/* tuiUpdateExecInfo */

enum tui_status
tui_alloc_source_buffer (struct tui_win_info *winInfo)
{
  register char *srcLineBuf;
  register int i, lineWidth, maxLines;
  enum tui_status ret = TUI_FAILURE;

  maxLines = winInfo->generic.height;	/* less the highlight box */
  lineWidth = winInfo->generic.width - 1;
  /*
     ** Allocate the buffer for the source lines.  Do this only once since they
     ** will be re-used for all source displays.  The only other time this will
     ** be done is when a window's size changes.
   */
  if (winInfo->generic.content == NULL)
    {
      srcLineBuf = (char *) xmalloc ((maxLines * lineWidth) * sizeof (char));
      if (srcLineBuf == (char *) NULL)
	fputs_unfiltered (
	   "Unable to Allocate Memory for Source or Disassembly Display.\n",
			   gdb_stderr);
      else
	{
	  /* allocate the content list */
	  if ((winInfo->generic.content =
	  (void **) tui_alloc_content (maxLines, SRC_WIN)) == NULL)
	    {
	      xfree (srcLineBuf);
	      srcLineBuf = (char *) NULL;
	      fputs_unfiltered (
				 "Unable to Allocate Memory for Source or Disassembly Display.\n",
				 gdb_stderr);
	    }
	}
      for (i = 0; i < maxLines; i++)
	((struct tui_win_element *)
	 winInfo->generic.content[i])->whichElement.source.line =
	  srcLineBuf + (lineWidth * i);
      ret = TUI_SUCCESS;
    }
  else
    ret = TUI_SUCCESS;

  return ret;
}				/* tuiAllocSourceBuffer */


/* Answer whether the a particular line number or address is displayed
   in the current source window.  */
int
tui_line_is_displayed (int line, struct tui_win_info * winInfo,
		       int checkThreshold)
{
  int isDisplayed = FALSE;
  int i, threshold;

  if (checkThreshold)
    threshold = SCROLL_THRESHOLD;
  else
    threshold = 0;
  i = 0;
  while (i < winInfo->generic.contentSize - threshold && !isDisplayed)
    {
      isDisplayed = (((struct tui_win_element *)
		      winInfo->generic.content[i])->whichElement.source.lineOrAddr.lineNo
		     == (int) line);
      i++;
    }

  return isDisplayed;
}


/* Answer whether the a particular line number or address is displayed
   in the current source window.  */
int
tui_addr_is_displayed (CORE_ADDR addr, struct tui_win_info * winInfo,
		    int checkThreshold)
{
  int isDisplayed = FALSE;
  int i, threshold;

  if (checkThreshold)
    threshold = SCROLL_THRESHOLD;
  else
    threshold = 0;
  i = 0;
  while (i < winInfo->generic.contentSize - threshold && !isDisplayed)
    {
      isDisplayed = (((struct tui_win_element *)
		      winInfo->generic.content[i])->whichElement.source.lineOrAddr.addr
		     == addr);
      i++;
    }

  return isDisplayed;
}


/*****************************************
** STATIC LOCAL FUNCTIONS               **
******************************************/
