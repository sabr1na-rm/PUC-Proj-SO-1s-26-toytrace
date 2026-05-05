#include "student_api.h"

int student_pair_syscall(struct syscall_pairer *pairer,
                         const struct syscall_event *ev,
                         struct syscall_event *out)
{
    static struct syscall_event entry_saved;
    static int has_entry = 0;
    
    if(ev->entering) 
    {
        entry_saved = *ev;
        has_entry = 1;
        
        return 0;
    }
    
    if(!ev->entering)
    {
        if(!has_entry || entry_saved.syscall_no != ev->syscall_no)
        {
            return -1;
        }
        
        *out = entry_saved;
        out->ret = ev->ret;
        out->entering = 0;
        
        has_entry = 0;
        
        return 1;
    }
    
    return -1;
}
