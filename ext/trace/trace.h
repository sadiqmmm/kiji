#include "st.h"

void rb_enable_tracing();
void rb_disable_tracing();
int rb_tracing_enabled_p();
char * rb_trace_file_id(int);
st_table* rb_line_stats();
