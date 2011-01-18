#include "ruby.h"
#include "st.h"

static VALUE Trace;

VALUE
tracer_enabled_p()
{
  return (rb_tracing_enabled_p() ? Qtrue : Qfalse);
}

VALUE
tracer_start()
{
  rb_enable_tracing();
  return Qnil;
}

VALUE
tracer_stop()
{
  rb_disable_tracing();
  return Qnil;
}

char*
type_string(int type) {
  switch (type) {
    case T_NONE:
      return "none";
    case T_NIL:
      return "nil";
    case T_OBJECT:
      return "object";
    case T_CLASS:
      return "class";
    case T_ICLASS:
      return "iclass";
    case T_MODULE:
      return "module";
    case T_FLOAT:
      return "float";
    case T_STRING:
      return "string";
    case T_REGEXP:
      return "regexp";
    case T_ARRAY:
      return "array";
    case T_FIXNUM:
      return "fixnum";
    case T_HASH:
      return "hash";
    case T_STRUCT:
      return "struct";
    case T_BIGNUM:
      return "bignum";
    case T_FILE:
      return "file";
    case T_TRUE:
      return "true";
    case T_FALSE:
      return "false";
    case T_DATA:
      return "data";
    case T_MATCH:
      return "match";
    case T_SYMBOL:
      return "symbol";
    case T_BLKTAG:
      return "blktag";
    case T_UNDEF:
      return "undef";
    case T_VARMAP:
      return "varmap";
    case T_SCOPE:
      return "scope";
    case T_NODE:
      return "node";
    default:
      return "unknown";
  }
}

VALUE
tracer_reset()
{
  rb_reset_tracing();
  return Qnil;
}

int
print_line_stats(st_data_t key, st_data_t value, st_data_t logfile)
{
  char *file;

  file = rb_trace_file_id((int)key);

  fprintf((FILE*)logfile, "rb_newobj count for %s: %i\n", file, (int)value);
  return 0;
}

VALUE
tracer_dump(VALUE self, VALUE _logfile)
{
  int i;

  Check_Type(_logfile, T_STRING);

  if (rb_tracing_enabled_p()) {
    object_stats_t stats = (object_stats_t)*rb_object_stats();
    FILE *logfile = fopen(StringValueCStr(_logfile), "w");

    if (logfile == NULL) {
      rb_raise(rb_eRuntimeError, "couldn't open trace file");
    }

    fprintf(logfile, "rb_newobj count: %i\n", stats.newobj_calls);

    for (i = 0; i < T_MASK + 1; i++) {
      if (stats.types[i] > 0) {
        fprintf(logfile, "%s count: %i\n", type_string(i), stats.types[i]);
      }
    }

    st_foreach((st_table*)rb_line_stats(), print_line_stats, (st_data_t)logfile);

    fprintf(logfile, "\n");
    fclose(logfile);
    rb_reset_tracing();
  }

  return Qnil;
}

void
Init_trace()
{
  Trace = rb_define_module("Trace");
  rb_define_singleton_method(Trace, "enabled?", tracer_enabled_p, 0);
  rb_define_singleton_method(Trace, "dump", tracer_dump, 1);
  rb_define_singleton_method(Trace, "start", tracer_start, 0);
  rb_define_singleton_method(Trace, "stop", tracer_stop, 0);
  rb_define_singleton_method(Trace, "reset", tracer_reset, 0);
}
