#include "student_api.h"
#include "syscall_names.h"
#include "trace_helpers.h"

#include <stdio.h>

void student_debug_raw_event(const struct syscall_event *ev,
                             char *buf,
                             size_t bufsz)
{
    if(ev->entering)
    {
        snprintf(buf, bufsz,
                 "pid=%d %s entrada args=(%#lx, %#lx, %#lx)",
                 ev->pid,
                 syscall_name(ev->syscall_no),
                 ev->args[0], ev->args[1], ev->args[2]);
    } else
    {
        snprintf(buf, bufsz,
                 "pid=%d %s saida ret=%ld",
                 ev->pid,
                 syscall_name(ev->syscall_no),
                 ev->ret);
    }
}

void student_format_event(const struct syscall_event *ev,
                          char *buf,
                          size_t bufsz)
{
     if (ev->syscall_no == SYS_read) {
        snprintf(buf, bufsz, "read(%#lx, %#lx, %#lx) = %ld",
                 ev->args[0], ev->args[1], ev->args[2], ev->ret);
        return;
    }
  
    if (ev->syscall_no == SYS_write) {
        snprintf(buf, bufsz, "write(%#lx, %#lx, %#lx) = %ld",
                 ev->args[0], ev->args[1], ev->args[2], ev->ret);
        return;
    }

    if (ev->syscall_no == SYS_openat) {
        char path[256];
        if (read_child_string(ev->pid, ev->args[1], path, sizeof(path)) < 0)
            strcpy(path, "<ilegivel>");
        snprintf(buf, bufsz, "openat(%#lx, \"%s\", %#lx, %#lx) = %ld",
                 ev->args[0], path, ev->args[2], ev->args[3], ev->ret);
        return;
    }

  if (ev->syscall_no == SYS_execve) {
        char path[256];
        if (read_child_string(ev->pid, ev->args[0], path, sizeof(path)) < 0)
            strcpy(path, "<ilegivel>");
        snprintf(buf, bufsz, "execve(\"%s\", %#lx, %#lx) = %ld",
                 path, ev->args[1], ev->args[2], ev->ret);
        return;
    }

    if (ev->syscall_no == SYS_exit_group) {
        snprintf(buf, bufsz, "exit_group(%#lx) = %ld", ev->args[0], ev->ret);
        return;
    }

    snprintf(buf, bufsz, "%s(%#lx, %#lx, %#lx, %#lx, %#lx, %#lx) = %ld",
             syscall_name(ev->syscall_no),
             ev->args[0], ev->args[1], ev->args[2],
             ev->args[3], ev->args[4], ev->args[5],
             ev->ret);
}
