#include "student_api.h"

#include "syscall_names.h"

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
    char path[256];

    switch(ev->syscall_no)
    {
    case 0:
        snprintf(buf, bufsz, "read(%ld, %#lx, %lu) = %ld",
                 (long)ev->args[0],
                 ev->args[1],
                 ev->args[2],
                 ev->ret);
        break;
    case 1:
        snprintf(buf, bufsz, "write(%ld, %#lx, %lu) = %ld",
                 (long)ev->arhs[0],
                 ev->args[1],
                 ev->args[2],
                 ev->ret);
        break;
    case 59:
        if (read_child_string(ev->pid, ev->args[0], path, sizeof(path)) < 0)
        {
            snprintf(path, sizeof(path), "<ilegivel>");
        }
        snprintf(buf, bufsz, "execve(\"%s\", ...) = %ld",
                 path,
                 ev->ret);
        break;
    case 257:
        if (read_child_string(ev->pid, ev->args[1], path, sizeof(path)) < 0)
        {
            snprintf(path, sizeof(path), "<ilegivel>");
        }
        snprintf(buf, bufsz, "openat(%ld, \"%s\", %#lx, %#lx) = %ld",
                 (long)ev->args[0],
                 path,
                 ev->args[2],
                 ev->args[3],
                 ev->ret);
        break;
    case 231:
        snprintf(buf, bufsz, "exit_group(%ld) = %ld",
                 (long)ev->args[0],
                 ev->ret);
        break;
    default:
        snprintf(buf, bufsz, "%s(%#lx, %#lx, %#lx, %#lx, %#lx, %#lx) = %ld",
                 syscall_name(ev->syscall_no),
                 ev->args[0], ev->args[1], ev->args[2],
                 ev->args[3], ev->args[4], ev->args[5],
                 ev->ret);
        break;
    }
