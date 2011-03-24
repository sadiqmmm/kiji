/**********************************************************************

  gc.c -

  $Author$
  $Date$
  created at: Tue Oct  5 09:44:46 JST 1993

  Copyright (C) 1993-2003 Yukihiro Matsumoto
  Copyright (C) 2000  Network Applied Communication Laboratory, Inc.
  Copyright (C) 2000  Information-technology Promotion Agency, Japan

**********************************************************************/

#include "ruby.h"
#include "rubysig.h"
#include "st.h"
#include "node.h"
#include "env.h"
#include "re.h"
#include <stdio.h>
#include <setjmp.h>
#include <math.h>
#include <sys/types.h>
#include <ctype.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#if defined _WIN32 || defined __CYGWIN__
#include <windows.h>
#endif

void re_free_registers _((struct re_registers*));
void rb_io_fptr_finalize _((struct rb_io_t*));

#define rb_setjmp(env) RUBY_SETJMP(env)
#define rb_jmp_buf rb_jmpbuf_t
#ifdef __CYGWIN__
int _setjmp(), _longjmp();
#endif

#define T_DEFERRED 0x3a

#ifndef GC_LEVEL_MAX  /*maximum # of VALUEs on 'C' stack during GC*/
#define GC_LEVEL_MAX  8000
#endif
#ifndef GC_STACK_PAD
#define GC_STACK_PAD  200  /* extra padding VALUEs for GC stack */
#endif
#define GC_STACK_MAX  (GC_LEVEL_MAX+GC_STACK_PAD)

/* The address of the end of the main thread's application stack. When the
 * main thread is active, application code may not cause the stack to grow
 * past this point. Past this point there's still a small area reserved for
 * garbage collector operations.
 */
static VALUE *stack_limit;
/*
 * The address of the end of the current thread's GC stack. When running
 * the GC, the stack may not grow past this point.
 * The value of this variable is reset every time garbage_collect() is
 * called.
 */
static VALUE *gc_stack_limit;

static void run_final();
static VALUE nomem_error;
static void garbage_collect(const char* reason);
static void add_to_longlife_recent_allocations(VALUE ptr);

#define DEFAULT_LONGLIFE_LAZINESS 0.05
static float longlife_laziness = DEFAULT_LONGLIFE_LAZINESS;
static int longlife_collection = Qfalse;
static int longlife_recent_allocations = 0;
int ruby_in_longlife_context = Qfalse;

typedef enum lifetime {
    lifetime_longlife,
    lifetime_eden
} lifetime_t;

#define OBJ_TYPE_COUNT (T_MASK + 1 + NODE_LAST)

#if HAVE_LONG_LONG
    #define GC_TIME_TYPE LONG_LONG
#else
    #define GC_TIME_TYPE long
#endif

static const char lifetime_name[][9] = { "Longlife", "Eden" };

#ifdef GC_DEBUG
static char *gc_data_file_name;
static char *gc_dump_file_pattern;
static char *backtrace_str_buffer = 0;
static int backtrace_str_buffer_len = 0;

int gc_debug_on = Qfalse;
static int gc_eden_cycles_since_last_longlife = 0;

static int gc_debug_summary = 0;
int gc_debug_dump = 0;
static int gc_debug_longlife_disabled = Qfalse;
static int gc_debug_stress = Qfalse;
static int gc_debug_always_mark = Qfalse;

#define SOURCE_POS_INIT_SIZE 100000
#define SOURCE_POS_INIT_TMP_SIZE 10000
static st_table *source_positions;

NODE* search_method(VALUE klass, ID id, VALUE *origin);
static const char lifetime_name_lower[][9] = { "longlife", "eden" };
#else
#define gc_debug_stress (0)
#define gc_debug_always_mark (0)
#endif

char* obj_type(int tp);
char* node_type(int tp);

#ifdef GC_DEBUG
/*
 *  call-seq:
 *    GC.stress                 => true or false
 *
 *  returns current status of GC stress mode.
 */

static VALUE
gc_debug_stress_get(self)
    VALUE self;
{
    return gc_debug_stress;
}

/*
 *  call-seq:
 *    GC.stress = bool          => bool
 *
 *  updates GC stress mode.
 *
 *  When GC.stress = true, GC is invoked for all GC opportunity:
 *  all memory and object allocation.
 *
 *  Since it makes Ruby very slow, it is only for debugging.
 */

static VALUE
gc_debug_stress_set(self, bool)
    VALUE self, bool;
{
    rb_secure(2);
    gc_debug_stress = RTEST(bool) ? Qtrue : Qfalse;
    return gc_debug_stress;
}

/*
 *  call-seq:
 *     GC.exorcise
 *
 *  Purge ghost references from recently freed stack space
 *
 */
static VALUE gc_exorcise(VALUE mod)
{
  rb_gc_wipe_stack();
  return Qnil;
}
#endif

NORETURN(void rb_exc_jump _((VALUE)));

#if defined(HAVE_LONG_LONG)
static unsigned long long allocated_objects = 0;
#else
static unsigned long allocated_objects = 0;
#endif

static int during_gc = 0;

void
rb_memerror()
{
    // If we throw a NoMemoryError, we're no longer doing GC. This will allow
    // further allocations to occur in the handler for this error. Normally,
    // it goes unhandled and terminates the VM, but even in that case,
    // rb_write_error2() will create one new string as part of printing the
    // error message to stderr. Allowing allocations in NoMemoryError handler
    // is okay -- by that time some or all of the stack frames were unwound,
    // so some memory can be realistically allocated again; even a GC can
    // succeed.
    during_gc = 0;
    rb_thread_t th = rb_curr_thread;
    during_gc = 0;
    if (!nomem_error ||
        (rb_thread_raised_p(th, RAISED_NOMEMORY) && rb_safe_level() < 4)) {
        fprintf(stderr, "[FATAL] failed to allocate memory\n");
        exit(EXIT_FAILURE);
    }
    if (rb_thread_raised_p(th, RAISED_NOMEMORY)) {
        rb_exc_jump(nomem_error);
    }
    rb_thread_raised_set(th, RAISED_NOMEMORY);
    rb_exc_raise(nomem_error);
}

void *
ruby_xmalloc(size)
    long size;
{
    void *mem;

    if (size < 0) {
        rb_raise(rb_eNoMemError, "negative allocation size (or too big)");
    }
    if (size == 0) {
        size = 1;
    }

    RUBY_CRITICAL(mem = malloc(size));
    if (!mem) {
        longlife_collection = Qtrue;
        garbage_collect("OOM in malloc");
        RUBY_CRITICAL(mem = malloc(size));
        if (!mem) {
            rb_memerror();
        }
    }

#if STACK_WIPE_SITES & 0x100
    rb_gc_update_stack_extent();
#endif
    return mem;
}

void *
ruby_xcalloc(n, size)
    long n, size;
{
    void *mem;

    mem = xmalloc(n * size);
    memset(mem, 0, n * size);

    return mem;
}

void *
ruby_xrealloc(ptr, size)
    void *ptr;
    long size;
{
    void *mem;

    if (size < 0) {
        rb_raise(rb_eArgError, "negative re-allocation size");
    }
    if (!ptr) {
      return xmalloc(size);
    }
    if (size == 0) {
      size = 1;
    }

    RUBY_CRITICAL(mem = realloc(ptr, size));
    if (!mem) {
        longlife_collection = Qtrue;
        garbage_collect("OOM in realloc()");
        RUBY_CRITICAL(mem = realloc(ptr, size));
        if (!mem) {
            rb_memerror();
        }
    }
#if STACK_WIPE_SITES & 0x200
    rb_gc_update_stack_extent();
#endif
    return mem;
}

void
ruby_xfree(x)
    void *x;
{
    if (x) {
        RUBY_CRITICAL(free(x));
    }
}

static int dont_gc;
static int need_call_final = 0;
static st_table *finalizer_table = 0;

/*******************************************************************/

/*
 *  call-seq:
 *     GC.enable    => true or false
 *
 *  Enables garbage collection, returning <code>true</code> if garbage
 *  collection was previously disabled.
 *
 *     GC.disable   #=> false
 *     GC.enable    #=> true
 *     GC.enable    #=> false
 *
 */

VALUE
rb_gc_enable()
{
    int old = dont_gc;

    dont_gc = Qfalse;
    return old;
}

/*
 *  call-seq:
 *     GC.disable    => true or false
 *
 *  Disables garbage collection, returning <code>true</code> if garbage
 *  collection was already disabled.
 *
 *     GC.disable   #=> false
 *     GC.disable   #=> true
 *
 */

VALUE
rb_gc_disable()
{
    int old = dont_gc;

    dont_gc = Qtrue;
    return old;
}

VALUE rb_mGC;

static struct gc_list {
    VALUE *varptr;
    struct gc_list *next;
} *global_List = 0;

void
rb_gc_register_address(addr)
    VALUE *addr;
{
    struct gc_list *tmp;

    tmp = ALLOC(struct gc_list);
    tmp->next = global_List;
    tmp->varptr = addr;
    global_List = tmp;
}

void
rb_gc_unregister_address(addr)
    VALUE *addr;
{
    struct gc_list *tmp = global_List;

    if (tmp->varptr == addr) {
        global_List = tmp->next;
        RUBY_CRITICAL(free(tmp));
        return;
    }
    while (tmp->next) {
        if (tmp->next->varptr == addr) {
            struct gc_list *t = tmp->next;

            tmp->next = tmp->next->next;
            RUBY_CRITICAL(free(t));
            break;
        }
        tmp = tmp->next;
    }
}

void
rb_global_variable(var)
    VALUE *var;
{
    rb_gc_register_address(var);
}

#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__CYGWIN__)
#pragma pack(push, 1) /* magic for reducing sizeof(RVALUE): 24 -> 20 */
#endif

static FILE* gc_data_file = NULL;

typedef struct RVALUE {
    union {
        struct {
            unsigned long flags;        /* always 0 for freed obj */
            struct RVALUE *next;
        } free;
        struct RBasic  basic;
        struct RObject object;
        struct RClass  klass;
        struct RFloat  flonum;
        struct RString string;
        struct RArray  array;
        struct RRegexp regexp;
        struct RHash   hash;
        struct RData   data;
        struct RStruct rstruct;
        struct RBignum bignum;
        struct RFile   file;
        struct RNode   node;
        struct RMatch  match;
        struct RVarmap varmap;
        struct SCOPE   scope;
    } as;
#ifdef GC_DEBUG
    source_position_t *source_pos;
#endif
} RVALUE;

#ifdef GC_DEBUG
int
gc_debug_check_printable(char *str)
{
    int j, str_len;
    if (!str) {
        return 0;
    }
    str_len = strlen(str);
    for (j = 0; j < str_len; j++) {
        if (!isprint(str[j])) {
            return 0;
        }
    }
    return 1;
}

static int
source_position_compare(source_position_t *x, source_position_t *y)
{
    return x->frames_hash != y->frames_hash;
}

static int
source_position_hash(source_position_t *x)
{
    return x->frames_hash;
}

static struct st_hash_type source_positions_type = {
    compare: source_position_compare,
    hash: source_position_hash
};

char *
gc_debug_get_backtrace(source_position_t *source_pos)
{
    size_t len;
    size_t backtrace_len = 0;
    char line_str[11];
    char cfunc_str[63];
    char *func_str;

    /* FIXME Some source_pos aren't correctly marked; thus the guards. */
    while (source_pos && gc_debug_check_printable(source_pos->file) && source_pos->line > -2 && source_pos->line < 1000000) {
        if (snprintf(line_str, sizeof(line_str), "%d", source_pos->line) > sizeof(line_str)) {
            rb_bug("Overflow on line_str");
        }

        func_str = rb_id2name(source_pos->func);
        if (!func_str) {
            /* Unknown internal address; can be converted to a function name via atos (OS X) or addr2name (Linux) */
            if (snprintf(cfunc_str, sizeof(cfunc_str), "<0x%x>", (unsigned int) source_pos->func) > sizeof(cfunc_str)) {
                rb_bug("Overflow on cfunc_str");
            }
            func_str = cfunc_str;
        }

        len = 3 + strlen(source_pos->file) + strlen(line_str) + (func_str ? strlen(func_str) + 1 : 0);

        if (backtrace_str_buffer_len < backtrace_len + len) {
            backtrace_str_buffer_len = backtrace_len + len;
            backtrace_str_buffer = realloc(backtrace_str_buffer, backtrace_str_buffer_len);
            if (!backtrace_str_buffer) {
                rb_bug("OOM on backtrace_str_buffer realloc");
            }
        }
        snprintf(backtrace_str_buffer + backtrace_len, len,
            " %s:%d%s%s",
            source_pos->file,
            source_pos->line,
            func_str ? "#" : "",
            func_str ? func_str : "");

        /* gc_debug_check_printable(backtrace_str_buffer); */
        backtrace_len += len - 1; /* overwrite \0 on next pass */
        source_pos = source_pos->parent;
    }
    return backtrace_str_buffer;
}

static int
gc_debug_print_source_locations(source_position_t *source_pos, int *counts, FILE *output_file)
{
    int i;
    char *backtrace_str = 0;

    for(i = 0; i < OBJ_TYPE_COUNT; i++) {
        if (counts[i] > 0) {
            if (!backtrace_str) {
                backtrace_str = gc_debug_get_backtrace(source_pos);
            }
            fprintf(output_file, "%8d %-15s%s\n",
                counts[i],
                i < T_NODE ? obj_type(i) : node_type(i - T_NODE),
                backtrace_str);
        }
    }
    free(counts);
    return ST_CONTINUE;
}

static source_position_t *
gc_debug_new_source_pos(char *file, int line, struct FRAME *frame)
{
    source_position_t *new_source_pos;
    source_position_t *source_pos;
    source_position_t *parent;
    NODE *func_node;
    ID func = 0;

    new_source_pos = malloc(sizeof(source_position_t));
    if (!new_source_pos) {
        rb_bug("OOM during source_position_list allocation");
    }

    if(frame) {
        parent = frame->source_pos;
        if (frame->last_func) {
            func = frame->last_func;
        } else if (frame->node) {
            if (nd_type(frame->node) == NODE_IFUNC) {
                func = (ID)frame->node->nd_cfnc;
            } else {
                func = frame->node->nd_mid;
            }
        }
    }
    else {
        parent = 0;
    }
    if (!func) {
        func = ruby_sourcefunc;
    }

    if(!file && frame) {
        func_node = search_method(frame->last_class, func, 0);
        if (func_node && func_node->nd_file) {
            file = func_node->nd_file;
        }
    }
    if (!file) {
        file = rb_source_filename("(ruby)");
    }

    new_source_pos->func = func;
    new_source_pos->file = file;
    new_source_pos->line = line;
    new_source_pos->parent = parent;
    new_source_pos->frames_hash =
        (parent ? parent->frames_hash * 31 * 31 * 31 : 0) +
        (VALUE) file * 31 * 31 +
        (VALUE) func * 31 +
        line;

    if (!st_lookup(source_positions, (st_data_t)new_source_pos, (st_data_t *)&source_pos)) {
        source_pos = new_source_pos;
        st_insert(source_positions, (st_data_t)(source_pos), (long int) source_pos);
    } else {
        free(new_source_pos);
    }
    return source_pos;
}

/**
  * Creates a source position for a stack frame. It will describe the location
  * of the call site for the call this frame belongs to.
  */
void
gc_debug_get_frame_source_pos(struct FRAME *frame) {
    char *file = 0;
    int line = 0;

    if (!(GC_DEBUG_ON && gc_debug_dump)) {
        return;
    }

    if (frame->node) {
        // Location of the call site in the caller
        file = frame->node->nd_file;
        line = nd_line(frame->node);
    }

    frame->source_pos = gc_debug_new_source_pos(file, line, frame->prev);
}

static source_position_t *
gc_debug_get_obj_source_pos()
{
    struct FRAME *frame = ruby_frame;
    char *file = 0;
    int line = 0;

    if (frame->last_func == ID_ALLOCATOR) {
        frame = frame->prev;
    }

    if (ruby_current_node) {
        file = ruby_current_node->nd_file;
        line = nd_line(ruby_current_node);
    }

    return gc_debug_new_source_pos(file, line, frame);
}

static void
gc_debug_add_to_source_pos_table(st_table *table, RVALUE *p, int type)
{
    int *counts;
    if (!st_lookup(table, (st_data_t)p->source_pos, (st_data_t *)&counts)) {
        counts = malloc(sizeof(int) * OBJ_TYPE_COUNT);
        MEMZERO(counts, int, OBJ_TYPE_COUNT);
        st_insert(table, (st_data_t)p->source_pos, (long int) counts);
    }

    if (type == T_NODE) type += nd_type(p);
    counts[type] +=1;
}

static void
gc_debug_dump_source_pos_table(st_table *table, lifetime_t lt, char *suffix)
{
    char fname[255];

    /* You can parse the output file with simple Unix tools. For example, to
        see objects that remain on the eden heap after collection, coalesce
        them by the first 5 backtrace lines, and pretty-print the output, run:

        cat /tmp/rb_gc_debug_objects.eden.live.txt |
        awk '
        BEGIN {} { sums[$2," ", $3, " ", $4, " ", $5, " ", $6, " ", $7, " ", $8] += $1 }
        END { for (i in sums) { print sums[i], i } }' |
        sort -rni |
        head -n 30 |
        ruby -e "STDIN.readlines.each {|l| puts l.split}"

    */

    snprintf(fname, 255, gc_dump_file_pattern, lifetime_name_lower[lt], suffix);
    FILE* output_file = fopen(fname, "w");
    if (!output_file) {
        GC_DEBUG_PRINTF("ERROR: Can't open %s for writing\n", fname);
        return;
    }
    st_foreach(table, gc_debug_print_source_locations, (long int)output_file);
}

#endif /* GC_DEBUG */

#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__CYGWIN__)
#pragma pack(pop)
#endif

static RVALUE *deferred_final_list = 0;

static int heaps_increment = 10;
static struct heaps_slot {
    void *membase;
    RVALUE *slot;
    int limit;
    RVALUE *slotlimit;
    int *marks;
    int marks_size;
    enum lifetime lifetime;
} *heaps;
static int heaps_length = 0;
static int heaps_used   = 0;

/* Too large a heap size and you can never free a page, due to fragmentation. Too
    small, and you have too many heaps and get stack errors. */
static int heap_size = 32768;
static int eden_heaps = 24;

typedef struct heaps_space {
    int heap_slots_total;
    int num_heaps;
    enum lifetime lifetime;
    RVALUE *freelist;
} heaps_space_t;

static heaps_space_t eden_heaps_space;
static heaps_space_t longlife_heaps_space;

typedef struct remembered_set {
    RVALUE *obj;
    struct remembered_set *next;
} remembered_set_t;

static remembered_set_t *remembered_set_ptr;
static remembered_set_t *remembered_set_freed;

typedef struct longlife_recent_allocations_set {
    RVALUE *obj;
    struct longlife_recent_allocations_set *next;
} longlife_recent_allocations_set_t;

static longlife_recent_allocations_set_t *longlife_recent_allocations_set_ptr;
static longlife_recent_allocations_set_t *longlife_recent_allocations_set_freed;

static RVALUE *himem, *lomem;

#include "marktable.h"
#include "marktable.c"

static int gc_cycles = 0;
static int gc_longlife_cycles = 0;

static void set_gc_parameters()
{

#define WITH_ENV_VAR(varname, variable, type, conv, cond, fmt) \
    do { \
        char* ptr = getenv(varname); \
        type val = variable; \
        char* __varname__ = varname; \
        char* __fmt__ = fmt; \
        if(ptr != NULL) { \
            val = conv(ptr); \
            if(cond) {
#define END_WITH_ENV_VAR } } if (gc_data_file) { GC_DEBUG_PRINTF(__fmt__, __varname__, val) } } while(0);

#define WITH_INT_ENV_VAR(varname, variable) WITH_ENV_VAR(varname, variable, int, atoi, val > 0, "%s=%d\n")
#define WITH_FLOAT_ENV_VAR(varname, variable) WITH_ENV_VAR(varname, variable, double, atof, val > 0, "%s=%f\n")

#define SET_INT_ENV_VAR(varname, variable) WITH_INT_ENV_VAR(varname, variable) variable = val; END_WITH_ENV_VAR
#define SET_FLOAT_ENV_VAR(varname, variable) WITH_FLOAT_ENV_VAR(varname, variable) variable = val; END_WITH_ENV_VAR
#define SET_BOOLEAN_ENV_VAR(varname, variable) WITH_INT_ENV_VAR(varname, variable) variable = Qtrue; END_WITH_ENV_VAR

#ifdef GC_DEBUG
    SET_BOOLEAN_ENV_VAR("RUBY_GC_DEBUG", gc_debug_on)
    if (gc_debug_on) {
      gc_data_file_name = getenv("RUBY_GC_DATA_FILE");
      if (gc_data_file_name == NULL) {
        gc_data_file_name = "/dev/stderr";
      }
      FILE* data_file = fopen(gc_data_file_name, "w");
      if (data_file != NULL) {
          gc_data_file = data_file;
      } else {
          fprintf(stderr, "Can't open RUBY_GC_DATA_FILE for writing\n");
          gc_data_file_name = "/dev/stderr";
          gc_data_file = fopen(gc_data_file_name, "w");
      }
    }

    gc_dump_file_pattern = getenv("RUBY_GC_DUMP_FILE_PATTERN");
    if(gc_dump_file_pattern == NULL) {
        gc_dump_file_pattern = "/tmp/rb_gc_debug_objects.%s.%s.txt";
    }
#endif

    SET_INT_ENV_VAR("RUBY_GC_HEAP_SIZE", heap_size)
    SET_INT_ENV_VAR("RUBY_GC_EDEN_HEAPS", eden_heaps)

    WITH_FLOAT_ENV_VAR("RUBY_GC_LONGLIFE_LAZINESS", longlife_laziness)
        if (val >= 1) {
          val = DEFAULT_LONGLIFE_LAZINESS;
        }
        longlife_laziness = val;
    END_WITH_ENV_VAR

#ifdef GC_DEBUG
    GC_DEBUG_PRINT("GC_DEBUG is available\n")
    SET_BOOLEAN_ENV_VAR("RUBY_GC_DEBUG_LONGLIFE_DISABLE", gc_debug_longlife_disabled)
    SET_BOOLEAN_ENV_VAR("RUBY_GC_DEBUG_STRESS", gc_debug_stress)
    SET_BOOLEAN_ENV_VAR("RUBY_GC_DEBUG_ALWAYS_MARK", gc_debug_always_mark)
    if (GC_DEBUG_ON) {
        SET_BOOLEAN_ENV_VAR("RUBY_GC_DEBUG_SUMMARY", gc_debug_summary)
        SET_BOOLEAN_ENV_VAR("RUBY_GC_DEBUG_DUMP", gc_debug_dump)
    }
#else
    GC_DEBUG_PRINT("GC_DEBUG not available (configure with --enable-gc-debug)\n")
#endif
}

/*
 *  call-seq:
 *     GC.log String  => String
 *
 *  Logs string to the GC data file and returns it.
 *
 *     GC.log "manual GC call"    #=> "manual GC call"
 *
 */

VALUE
rb_gc_log(self, original_str)
     VALUE self, original_str;
{
    if (original_str == Qnil) {
        fprintf(gc_data_file, "\n");
    }
    else {
        VALUE str = StringValue(original_str);
        char *p = RSTRING(str)->ptr;
        fprintf(gc_data_file, "%s\n", p);
    }
    return original_str;
}


static inline void push_freelist(heaps_space_t *heaps_space, RVALUE *p)
{
    MEMZERO((void*)p, RVALUE, 1);
    p->as.free.next = heaps_space->freelist;
    heaps_space->freelist = p;
}

static int
add_heap(heaps_space_t *heaps_space)
{
    RVALUE *p, *pend;
    int new_heap_size = heap_size;

    if (heaps_used == heaps_length) {
        /* Realloc heaps */
        struct heaps_slot *p;
        int length;

        heaps_length += heaps_increment;
        length = heaps_length*sizeof(struct heaps_slot);
        RUBY_CRITICAL(
            if (heaps_used > 0) {
                p = (struct heaps_slot *)realloc(heaps, length);
                if (p) {
                  heaps = p;
                }
            }
            else {
                p = heaps = (struct heaps_slot *)malloc(length);
            });
        if (p == 0) {
          rb_memerror();
        }
    }

    for (;;) {
        RUBY_CRITICAL(p = (RVALUE*)malloc(sizeof(RVALUE)*(new_heap_size)));
        if (p == 0) {
          rb_memerror();
        }
        heaps[heaps_used].membase = p;

        // Align heap pointer to RVALUE size, if necessary
        if ((VALUE)p % sizeof(RVALUE) != 0) {
            p = (RVALUE*)((VALUE)p + sizeof(RVALUE) - ((VALUE)p % sizeof(RVALUE)));
            new_heap_size--;
        }

        heaps[heaps_used].slot = p;
        heaps[heaps_used].limit = new_heap_size;
        heaps[heaps_used].slotlimit = p + new_heap_size;
        heaps[heaps_used].marks_size = (int) (ceil(new_heap_size / (sizeof(int) * 8.0)));
        heaps[heaps_used].marks = (int *) calloc(heaps[heaps_used].marks_size, sizeof(int));
        heaps[heaps_used].lifetime = heaps_space->lifetime;
        break;
    }
    pend = p + new_heap_size;
    if (lomem == 0 || lomem > p) {
      lomem = p;
    }
    if (himem < pend) {
      himem = pend;
    }
    heaps_space->heap_slots_total += new_heap_size;
    heaps_space->num_heaps++;
    heaps_used++;

    /* Add to freelist in reverse order. */
    while (pend > p) {
        pend--;
        push_freelist(heaps_space, pend);
    }

    return new_heap_size;
}

#define RANY(o) ((RVALUE*)(o))

int
rb_during_gc()
{
    return during_gc;
}

static inline VALUE
pop_freelist(heaps_space_t* heaps_space)
{
    VALUE obj = (VALUE)heaps_space->freelist;
    heaps_space->freelist = heaps_space->freelist->as.free.next;
    RANY(obj)->as.free.next = 0;
#ifdef GC_DEBUG
    MEMZERO((void*)obj, RVALUE, 1);
    if (GC_DEBUG_ON && gc_debug_dump) {
        RANY(obj)->source_pos = gc_debug_get_obj_source_pos();
    }
#endif
    return obj;
}

static inline void
add_heap_if_needed(heaps_space_t* heaps_space)
{
    int new_heap_size;
    if (!heaps_space->freelist) {
        new_heap_size = add_heap(heaps_space);
        GC_DEBUG_PRINTF("*** %s heap added (out of space) (size %d) ***\n",
          lifetime_name[heaps_space->lifetime], new_heap_size)
    }
}

/* Make perftools.rb install ok */
VALUE
rb_newobj(int type)
{
    return rb_newobj_eden(type);
}

VALUE
rb_newobj_eden(int type)
{
    VALUE obj;

#ifdef GC_DEBUG
    if (during_gc) {
        rb_bug("object allocation during garbage collection phase");
    }
    if (gc_debug_stress) {
        longlife_collection = Qtrue;
        garbage_collect("GC stress is enabled");
    }
#endif
    if (!eden_heaps_space.freelist) {
      garbage_collect("no free space in the eden");
    }

    add_heap_if_needed(&eden_heaps_space);
    obj = pop_freelist(&eden_heaps_space);

    allocated_objects++;
    return obj;
}

VALUE
rb_newobj_longlife(int type)
{
    VALUE obj;

#ifdef GC_DEBUG
    if (gc_debug_longlife_disabled) {
        return rb_newobj_eden(type);
    }
    if (during_gc) {
        rb_bug("object allocation during garbage collection phase");
    }
    if (gc_debug_stress) {
        longlife_collection = Qtrue;
        garbage_collect("GC stress is enabled");
    }
#endif
    if (!longlife_heaps_space.freelist) {
        longlife_collection = Qtrue;
        garbage_collect("no free space in the longlife");
    }

    add_heap_if_needed(&longlife_heaps_space);
    obj = pop_freelist(&longlife_heaps_space);
    RBASIC(obj)->flags |= (FL_LONGLIFE|FL_MOVE);

    add_to_longlife_recent_allocations(obj);

    allocated_objects++;
    return obj;
}

VALUE
rb_data_object_alloc(klass, datap, dmark, dfree)
    VALUE klass;
    void *datap;
    RUBY_DATA_FUNC dmark;
    RUBY_DATA_FUNC dfree;
{
    NEWOBJ(data, struct RData);
    if (klass) {
      Check_Type(klass, T_CLASS);
    }
    OBJSETUP(data, klass, T_DATA);
    data->data = datap;
    data->dfree = dfree;
    data->dmark = dmark;

    return (VALUE)data;
}

extern st_table *rb_class_tbl;
VALUE *rb_gc_stack_start = 0;
#ifdef __ia64
VALUE *rb_gc_register_stack_start = 0;
#endif


#ifdef DJGPP
/* set stack size (http://www.delorie.com/djgpp/v2faq/faq15_9.html) */
unsigned int _stklen = 0x180000; /* 1.5 kB */
#endif

#if defined(DJGPP) || defined(_WIN32_WCE)
static unsigned int STACK_LEVEL_MAX = 65535;
#elif defined(__human68k__)
unsigned int _stacksize = 262144;
# define STACK_LEVEL_MAX (_stacksize - 4096)
# undef HAVE_GETRLIMIT
#elif defined(HAVE_GETRLIMIT) || defined(_WIN32)
static size_t STACK_LEVEL_MAX = 655300;
#else
# define STACK_LEVEL_MAX 655300
#endif

#ifndef nativeAllocA
  /* portable way to return an approximate stack pointer */
NOINLINE(VALUE *__sp(void));
VALUE *__sp(void) {
  VALUE tos;
  return &tos;
}
# define SET_STACK_END VALUE stack_end
# define STACK_END (&stack_end)
#else
# define SET_STACK_END ((void)0)
# define STACK_END __sp()
#endif

#if STACK_GROW_DIRECTION < 0
# define STACK_LENGTH(start)  ((start) - STACK_END)
#elif STACK_GROW_DIRECTION > 0
# define STACK_LENGTH(start)  (STACK_END - (start) + 1)
#else
# define STACK_LENGTH(start)  ((STACK_END < (start)) ? (start) - STACK_END\
                                           : STACK_END - (start) + 1)
#endif
#if STACK_GROW_DIRECTION > 0
# define STACK_UPPER(a, b) a
#elif STACK_GROW_DIRECTION < 0
# define STACK_UPPER(a, b) b
#else
int rb_gc_stack_grow_direction;
static int
stack_grow_direction(addr)
    VALUE *addr;
{
    SET_STACK_END;
    return rb_gc_stack_grow_direction = STACK_END > addr ? 1 : -1;
}
# define STACK_UPPER(a, b) (rb_gc_stack_grow_direction > 0 ? a : b)
#endif

size_t
ruby_stack_length(base)
    VALUE **base;
{
    SET_STACK_END;
    VALUE *start;
    if (rb_curr_thread == rb_main_thread) {
        start = rb_gc_stack_start;
    } else {
        start = rb_curr_thread->stk_base;
    }
    if (base) {
      *base = STACK_UPPER(start, STACK_END);
    }
    return STACK_LENGTH(start);
}

int
ruby_stack_check()
{
    SET_STACK_END;
    if (!rb_main_thread || rb_curr_thread == rb_main_thread) {
        return __stack_past(stack_limit, STACK_END);
    } else {
        /* ruby_stack_check() is only called periodically, but we want to
         * detect a stack overflow before the thread's guard area is accessed.
         * So we append a '+ getpagesize()' to the address check.
         *
         * TODO: support architectures on which the stack grows upwards.
         */
        return __stack_past(rb_curr_thread->guard + getpagesize(), STACK_END);
    }
}

/*
  Zero memory that was (recently) part of the stack, but is no longer.
  Invoke when stack is deep to mark its extent and when it's shallow to wipe it.
*/
#if STACK_WIPE_METHOD != 4
#if STACK_WIPE_METHOD
void rb_gc_wipe_stack(void)
{
  if (rb_curr_thread) {
    VALUE *stack_end = rb_curr_thread->gc_stack_end;
    VALUE *sp = __sp();
    rb_curr_thread->gc_stack_end = sp;
#if STACK_WIPE_METHOD == 1
#warning clearing of "ghost references" from the call stack has been disabled
#elif STACK_WIPE_METHOD == 2  /* alloca ghost stack before clearing it */
    if (__stack_past(sp, stack_end)) {
      size_t bytes = __stack_depth((char *)stack_end, (char *)sp);
      STACK_UPPER(sp = nativeAllocA(bytes), stack_end = nativeAllocA(bytes));
      __stack_zero(stack_end, sp);
    }
#elif STACK_WIPE_METHOD == 3    /* clear unallocated area past stack pointer */
    __stack_zero(stack_end, sp);  /* will crash if compiler pushes a temp. here */
#else
#error unsupported method of clearing ghost references from the stack
#endif
  }
}
#else
#warning clearing of "ghost references" from the call stack completely disabled
#endif
#endif

#define MARK_STACK_MAX 1024
static VALUE mark_stack[MARK_STACK_MAX];
static VALUE *mark_stack_ptr;
static int mark_stack_overflow;

static void
init_mark_stack()
{
    mark_stack_overflow = 0;
    mark_stack_ptr = mark_stack;
}

#define MARK_STACK_EMPTY (mark_stack_ptr == mark_stack)

static inline void
push_mark_stack(VALUE ptr)
{
    if (!mark_stack_overflow) {
        if (mark_stack_ptr - mark_stack < MARK_STACK_MAX) {
            *mark_stack_ptr++ = ptr;
        } else {
            mark_stack_overflow = 1;
        }
    }
}

static st_table *source_filenames;

void
Init_source_filenames()
{
    source_filenames = st_init_strtable();
}

char *
rb_source_filename(f)
    const char *f;
{
    st_data_t name;

    if (!st_lookup(source_filenames, (st_data_t)f, &name)) {
        long len = strlen(f) + 1;
        char *ptr = ALLOC_N(char, len + 1);
        name = (st_data_t)ptr;
        *ptr++ = 0;
        MEMCPY(ptr, f, char, len);
        st_add_direct(source_filenames, (st_data_t)ptr, name);
        return ptr;
    }
    return (char *)name + 1;
}

static void
mark_source_filename(f)
    char *f;
{
    if (f) {
        rb_mark_table_add_filename(f);
    }
}

static int
sweep_source_filename(key, value)
    char *key, *value;
{
    if (rb_mark_table_contains_filename(value + 1)) {
        rb_mark_table_remove_filename(value + 1);
        return ST_CONTINUE;
    }
    else {
        rb_mark_table_remove_filename(value + 1);
        free(value);
        return ST_DELETE;
    }
}

#ifdef GC_DEBUG
void
Init_source_positions()
{
    source_positions = st_init_table_with_size(&source_positions_type, SOURCE_POS_INIT_SIZE);
}

static void
mark_source_pos(source_position_t *source_pos)
{
    if (GC_DEBUG_ON && gc_debug_dump && longlife_collection && source_pos) {
        if (!rb_mark_table_contains_source_pos(source_pos)) {
            rb_mark_table_add_source_pos(source_pos);
            mark_source_filename(source_pos->file);
            mark_source_pos(source_pos->parent);
        }
    }
}

static int
sweep_source_pos(char *key, source_position_t *source_pos)
{
    if (rb_mark_table_contains_source_pos(source_pos)) {
        rb_mark_table_remove_source_pos(source_pos);
        return ST_CONTINUE;
    }
    else {
        rb_mark_table_remove_source_pos(source_pos);
        st_delete(source_positions, (st_data_t *)source_pos, 0);
        free(source_pos);
        return ST_DELETE;
    }
}
#endif

static void gc_mark_children _((VALUE ptr));

static void
gc_mark_all()
{
    RVALUE *p, *pend;
    struct heaps_slot *heap = heaps+heaps_used;

    init_mark_stack();
    while (--heap >= heaps) {
        p = heap->slot; pend = p + heap->limit;
        while (p < pend) {
            if (rb_mark_table_heap_contains(heap, p) &&
                BUILTIN_TYPE(p) != T_DEFERRED) {
                gc_mark_children((VALUE)p);
            }
            p++;
        }
    }
}

static void
gc_mark_rest()
{
    size_t stackLen = mark_stack_ptr - mark_stack;
#ifdef nativeAllocA
    VALUE *tmp_arry = nativeAllocA(stackLen*sizeof(VALUE));
#else
    VALUE tmp_arry[MARK_STACK_MAX];
#endif
    VALUE *p = tmp_arry + stackLen;

    MEMCPY(tmp_arry, mark_stack, VALUE, stackLen);

    init_mark_stack();
    while(--p >= tmp_arry) gc_mark_children(*p);
}

static inline int
is_pointer_to_heap(ptr)
    void *ptr;
{
    RVALUE *p = RANY(ptr);
    struct heaps_slot *heap;

    if (p < lomem || p > himem || (VALUE)p % sizeof(RVALUE)) {
      return Qfalse;
    }

    /* check if p looks like a pointer */
    heap = heaps+heaps_used;
    while (--heap >= heaps) {
        if (p >= heap->slot && p < heap->slot + heap->limit) {
            return Qtrue;
        }
    }
    return Qfalse;
}

static inline int
is_pointer_to_longlife_heap(ptr)
    void *ptr;
{
    RVALUE *p = RANY(ptr);
    struct heaps_slot *heap;

    if (p < lomem || p > himem || (VALUE)p % sizeof(RVALUE)) {
        return Qfalse;
    }

    /* check if p looks like a pointer */
    heap = heaps+heaps_used;
    while (--heap >= heaps) {
        if (p >= heap->slot && p < heap->slot + heap->limit && heap->lifetime == lifetime_longlife) {
            return Qtrue;
        }
    }
    return Qfalse;
}

static void
add_to_longlife_recent_allocations(VALUE ptr)
{
    longlife_recent_allocations_set_t *tmp;
    if (longlife_recent_allocations_set_freed) {
        tmp = longlife_recent_allocations_set_freed;
        longlife_recent_allocations_set_freed = longlife_recent_allocations_set_freed->next;
    }
    else {
        tmp = ALLOC(longlife_recent_allocations_set_t);
    }
    tmp->next = longlife_recent_allocations_set_ptr;
    tmp->obj = (RVALUE *)ptr;
    longlife_recent_allocations_set_ptr = tmp;
}

/* Call this if you mutate an object that might be on the longlife heap. */
void
maybe_add_to_longlife_recent_allocations(VALUE ptr)
{
    if (ptr && OBJ_LONGLIVED(ptr)) {
        add_to_longlife_recent_allocations(ptr);
    }
}

static VALUE
rb_gc_write_barrier(VALUE ptr)
{
    RVALUE *obj = RANY(ptr);

    if (ptr && !SPECIAL_CONST_P(ptr) && obj->as.basic.flags && !(RBASIC(ptr)->flags & (FL_REMEMBERED_SET|FL_LONGLIFE))) {
        remembered_set_t *tmp;
        if (remembered_set_freed) {
            tmp = remembered_set_freed;
            remembered_set_freed = remembered_set_freed->next;
        }
        else {
            tmp = ALLOC(remembered_set_t);
        }
        tmp->next = remembered_set_ptr;
        tmp->obj = obj;
        obj->as.basic.flags |= FL_REMEMBERED_SET;
        remembered_set_ptr = tmp;
    }
    return ptr;
}

static void
mark_locations_array(x, n)
    VALUE *x;
    size_t n;
{
    VALUE v;
    while (n--) {
        v = *x;
        if (is_pointer_to_heap((void *)v)) {
            rb_gc_mark(v);
        }
        x++;
    }
}

inline void
rb_gc_mark_locations(start, end)
    VALUE *start, *end;
{
    mark_locations_array(start,end - start);
}

static int
mark_entry(key, value)
    ID key;
    VALUE value;
{
    rb_gc_mark(value);
    return ST_CONTINUE;
}

void
rb_mark_tbl(tbl)
    st_table *tbl;
{
    if (!tbl) return;
    st_foreach(tbl, mark_entry, 0);
}
#define mark_tbl(tbl)  rb_mark_tbl(tbl)

static int
mark_keyvalue(key, value)
    VALUE key;
    VALUE value;
{
    rb_gc_mark(key);
    rb_gc_mark(value);
    return ST_CONTINUE;
}

static int
mark_key(key, value)
    VALUE key, value;
{
    rb_gc_mark(key);
    return ST_CONTINUE;
}

void
rb_mark_set(tbl)
    st_table *tbl;
{
    if (!tbl) return;
    st_foreach(tbl, mark_key, 0);
}
#define mark_set(tbl)  rb_mark_set(tbl)

void
rb_mark_hash(tbl)
    st_table *tbl;
{
    if (!tbl) return;
    st_foreach(tbl, mark_keyvalue, 0);
}
#define mark_hash(tbl)  rb_mark_hash(tbl)

void
rb_gc_mark_maybe(obj)
    VALUE obj;
{
    if (is_pointer_to_heap((void *)obj)) {
        rb_gc_mark(obj);
    }
}

void
rb_gc_mark(ptr)
    VALUE ptr;
{
    RVALUE *obj = RANY(ptr);
    SET_STACK_END;

    if (rb_special_const_p(ptr)) return; /* special const not marked */
    if (obj->as.basic.flags == 0) return;       /* free cell */
    if (rb_mark_table_contains(obj)) return;  /* already marked */

    rb_mark_table_add(obj);
#ifdef GC_DEBUG
    mark_source_pos(obj->source_pos);
#endif

    if (__stack_past(gc_stack_limit, STACK_END))
      push_mark_stack(ptr);
    else{
      gc_mark_children(ptr);
    }
}

static void
gc_mark_children(ptr)
    VALUE ptr;
{
    RVALUE *obj = RANY(ptr);

    goto marking;               /* skip */

  again:
    obj = RANY(ptr);
    if (rb_special_const_p(ptr)) return; /* special const not marked */
    if (obj->as.basic.flags == 0) return;       /* free cell */
    if (!(longlife_collection || gc_debug_always_mark) && OBJ_LONGLIVED(obj)) return; /* ref from normal to longlife */
    if (rb_mark_table_contains(obj)) return;  /* already marked */

    rb_mark_table_add(obj);
#ifdef GC_DEBUG
    mark_source_pos(obj->source_pos);
#endif

  marking:
    if (FL_TEST(obj, FL_EXIVAR)) {
        rb_mark_generic_ivar(ptr);
    }

    switch (obj->as.basic.flags & T_MASK) {
      case T_NIL:
      case T_FIXNUM:
        rb_bug("rb_gc_mark() called for broken object");
        break;

      case T_NODE:
        if (longlife_collection) {
            mark_source_filename(obj->as.node.nd_file);
        }
        switch (nd_type(obj)) {
          case NODE_IF:         /* 1,2,3 */
          case NODE_FOR:
          case NODE_ITER:
          case NODE_CREF:
          case NODE_WHEN:
          case NODE_MASGN:
          case NODE_RESCUE:
          case NODE_RESBODY:
          case NODE_CLASS:
            rb_gc_mark((VALUE)obj->as.node.u2.node);
            /* fall through */
          case NODE_BLOCK:      /* 1,3 */
          case NODE_ARRAY:
          case NODE_DSTR:
          case NODE_DXSTR:
          case NODE_DREGX:
          case NODE_DREGX_ONCE:
          case NODE_FBODY:
          case NODE_ENSURE:
          case NODE_CALL:
          case NODE_DEFS:
          case NODE_OP_ASGN1:
            rb_gc_mark((VALUE)obj->as.node.u1.node);
            /* fall through */
          case NODE_SUPER:      /* 3 */
          case NODE_FCALL:
          case NODE_DEFN:
          case NODE_NEWLINE:
            ptr = (VALUE)obj->as.node.u3.node;
            goto again;

          case NODE_WHILE:      /* 1,2 */
          case NODE_UNTIL:
          case NODE_AND:
          case NODE_OR:
          case NODE_CASE:
          case NODE_SCLASS:
          case NODE_DOT2:
          case NODE_DOT3:
          case NODE_FLIP2:
          case NODE_FLIP3:
          case NODE_MATCH2:
          case NODE_MATCH3:
          case NODE_OP_ASGN_OR:
          case NODE_OP_ASGN_AND:
          case NODE_MODULE:
          case NODE_ALIAS:
          case NODE_VALIAS:
          case NODE_ARGS:
            rb_gc_mark((VALUE)obj->as.node.u1.node);
            /* fall through */
          case NODE_METHOD:     /* 2 */
          case NODE_NOT:
          case NODE_GASGN:
          case NODE_LASGN:
          case NODE_DASGN:
          case NODE_DASGN_CURR:
          case NODE_IASGN:
          case NODE_CVDECL:
          case NODE_CVASGN:
          case NODE_COLON3:
          case NODE_OPT_N:
          case NODE_EVSTR:
          case NODE_UNDEF:
            ptr = (VALUE)obj->as.node.u2.node;
            goto again;

          case NODE_HASH:       /* 1 */
          case NODE_LIT:
          case NODE_STR:
          case NODE_XSTR:
          case NODE_DEFINED:
          case NODE_MATCH:
          case NODE_RETURN:
          case NODE_BREAK:
          case NODE_NEXT:
          case NODE_YIELD:
          case NODE_COLON2:
          case NODE_SPLAT:
          case NODE_TO_ARY:
          case NODE_SVALUE:
            ptr = (VALUE)obj->as.node.u1.node;
            goto again;

          case NODE_SCOPE:      /* 2,3 */
          case NODE_BLOCK_PASS:
          case NODE_CDECL:
            rb_gc_mark((VALUE)obj->as.node.u3.node);
            ptr = (VALUE)obj->as.node.u2.node;
            goto again;

          case NODE_ZARRAY:     /* - */
          case NODE_ZSUPER:
          case NODE_CFUNC:
          case NODE_VCALL:
          case NODE_GVAR:
          case NODE_LVAR:
          case NODE_DVAR:
          case NODE_IVAR:
          case NODE_CVAR:
          case NODE_NTH_REF:
          case NODE_BACK_REF:
          case NODE_REDO:
          case NODE_RETRY:
          case NODE_SELF:
          case NODE_NIL:
          case NODE_TRUE:
          case NODE_FALSE:
          case NODE_ATTRSET:
          case NODE_BLOCK_ARG:
          case NODE_POSTEXE:
            break;
          case NODE_ALLOCA:
            mark_locations_array((VALUE*)obj->as.node.u1.value,
                                 obj->as.node.u3.cnt);
            ptr = (VALUE)obj->as.node.u2.node;
            goto again;

          default:              /* unlisted NODE */
            if (is_pointer_to_heap(obj->as.node.u1.node)) {
                rb_gc_mark((VALUE)obj->as.node.u1.node);
            }
            if (is_pointer_to_heap(obj->as.node.u2.node)) {
                rb_gc_mark((VALUE)obj->as.node.u2.node);
            }
            if (is_pointer_to_heap(obj->as.node.u3.node)) {
                ptr = (VALUE)obj->as.node.u3.node;
                goto again;
            }
        }
        return; /* no need to mark class. */
    }

    rb_gc_mark(obj->as.basic.klass);
    switch (obj->as.basic.flags & T_MASK) {
      case T_ICLASS:
      case T_CLASS:
      case T_MODULE:
        mark_tbl(obj->as.klass.m_tbl);
        mark_tbl(obj->as.klass.iv_tbl);
        ptr = obj->as.klass.super;
        goto again;

      case T_ARRAY:
        if (FL_TEST(obj, ELTS_SHARED)) {
            ptr = obj->as.array.aux.shared;
            goto again;
        }
        else {
            VALUE *ptr = obj->as.array.ptr;
            VALUE *pend = ptr + obj->as.array.len;
            while (ptr < pend) {
                rb_gc_mark(*ptr++);
            }
        }
        break;

      case T_HASH:
        mark_hash(obj->as.hash.tbl);
        ptr = obj->as.hash.ifnone;
        goto again;

      case T_STRING:
#define STR_ASSOC FL_USER3   /* copied from string.c */
        if (FL_TEST(obj, ELTS_SHARED|STR_ASSOC)) {
            ptr = obj->as.string.aux.shared;
            goto again;
        }
        break;

      case T_DATA:
        if (obj->as.data.dmark) (*obj->as.data.dmark)(DATA_PTR(obj));
        break;

      case T_OBJECT:
        mark_tbl(obj->as.object.iv_tbl);
        break;

      case T_FILE:
      case T_REGEXP:
      case T_FLOAT:
      case T_BIGNUM:
      case T_BLKTAG:
        break;

      case T_MATCH:
        if (obj->as.match.str) {
            ptr = obj->as.match.str;
            goto again;
        }
        break;

      case T_VARMAP:
        rb_gc_mark(obj->as.varmap.val);
        ptr = (VALUE)obj->as.varmap.next;
        goto again;

      case T_SCOPE:
        if (obj->as.scope.local_vars && (obj->as.scope.flags & SCOPE_MALLOC)) {
            int n = obj->as.scope.local_tbl[0]+1;
            VALUE *vars = &obj->as.scope.local_vars[-1];

            while (n--) {
                rb_gc_mark(*vars++);
            }
        }
        break;

      case T_STRUCT:
        {
            VALUE *ptr = obj->as.rstruct.ptr;
            VALUE *pend = ptr + obj->as.rstruct.len;
            while (ptr < pend)
               rb_gc_mark(*ptr++);
        }
        break;

      default:
        rb_bug("rb_gc_mark(): unknown data type 0x%lx(0x%lx) %s",
               obj->as.basic.flags & T_MASK, obj,
               is_pointer_to_heap(obj) ? "corrupted object" : "non object");
    }
}

static int obj_free _((VALUE));

static void add_to_correct_freelist(RVALUE *p)
{
    int longlived = OBJ_LONGLIVED(p);
    // Has explicit longlife flag
    if(longlived) {
        push_freelist(&longlife_heaps_space, p);
    }
    // Has some flags (so they weren't cleared), but not longlife
    else if(p->as.free.flags != 0 && !longlived) {
        push_freelist(&eden_heaps_space, p);
    }
    // If all else fails, use slower is_pointer_to_longlife_heap()
    else {
        push_freelist(is_pointer_to_longlife_heap(p) ? &longlife_heaps_space : &eden_heaps_space, p);
    }
}

static void
finalize_list(p)
    RVALUE *p;
{
    while (p) {
        RVALUE *tmp = p->as.free.next;
        run_final((VALUE)p);
        /* Don't free objects that are singletons, or objects that are already freed.
         * The latter is to prevent the unnecessary marking of memory pages as dirty,
         * which can destroy copy-on-write semantics.
         */
        if (!FL_TEST(p, FL_SINGLETON)) {
            rb_mark_table_remove(p);
            add_to_correct_freelist(p);
        }
        p = tmp;
    }
}

#define CONST_TO_NAME(x) case x: return #x;

char* obj_type(int tp)
{
    switch (tp) {
        CONST_TO_NAME(T_NIL)
        CONST_TO_NAME(T_OBJECT)
        CONST_TO_NAME(T_CLASS)
        CONST_TO_NAME(T_ICLASS)
        CONST_TO_NAME(T_MODULE)
        CONST_TO_NAME(T_FLOAT)
        CONST_TO_NAME(T_STRING)
        CONST_TO_NAME(T_REGEXP)
        CONST_TO_NAME(T_ARRAY)
        CONST_TO_NAME(T_FIXNUM)
        CONST_TO_NAME(T_HASH)
        CONST_TO_NAME(T_STRUCT)
        CONST_TO_NAME(T_BIGNUM)
        CONST_TO_NAME(T_FILE)

        CONST_TO_NAME(T_TRUE)
        CONST_TO_NAME(T_FALSE)
        CONST_TO_NAME(T_DATA)
        CONST_TO_NAME(T_MATCH)
        CONST_TO_NAME(T_SYMBOL)

        CONST_TO_NAME(T_BLKTAG)
        CONST_TO_NAME(T_UNDEF)
        CONST_TO_NAME(T_VARMAP)
        CONST_TO_NAME(T_SCOPE)
        CONST_TO_NAME(T_NODE)
        default: return "____";
    }
}

char* node_type(int tp)
{
    switch (tp) {
        CONST_TO_NAME(NODE_METHOD)
        CONST_TO_NAME(NODE_FBODY)
        CONST_TO_NAME(NODE_CFUNC)
        CONST_TO_NAME(NODE_SCOPE)
        CONST_TO_NAME(NODE_BLOCK)
        CONST_TO_NAME(NODE_IF)
        CONST_TO_NAME(NODE_CASE)
        CONST_TO_NAME(NODE_WHEN)
        CONST_TO_NAME(NODE_OPT_N)
        CONST_TO_NAME(NODE_WHILE)
        CONST_TO_NAME(NODE_UNTIL)
        CONST_TO_NAME(NODE_ITER)
        CONST_TO_NAME(NODE_FOR)
        CONST_TO_NAME(NODE_BREAK)
        CONST_TO_NAME(NODE_NEXT)
        CONST_TO_NAME(NODE_REDO)
        CONST_TO_NAME(NODE_RETRY)
        CONST_TO_NAME(NODE_BEGIN)
        CONST_TO_NAME(NODE_RESCUE)
        CONST_TO_NAME(NODE_RESBODY)
        CONST_TO_NAME(NODE_ENSURE)
        CONST_TO_NAME(NODE_AND)
        CONST_TO_NAME(NODE_OR)
        CONST_TO_NAME(NODE_NOT)
        CONST_TO_NAME(NODE_MASGN)
        CONST_TO_NAME(NODE_LASGN)
        CONST_TO_NAME(NODE_DASGN)
        CONST_TO_NAME(NODE_DASGN_CURR)
        CONST_TO_NAME(NODE_GASGN)
        CONST_TO_NAME(NODE_IASGN)
        CONST_TO_NAME(NODE_CDECL)
        CONST_TO_NAME(NODE_CVASGN)
        CONST_TO_NAME(NODE_CVDECL)
        CONST_TO_NAME(NODE_OP_ASGN1)
        CONST_TO_NAME(NODE_OP_ASGN2)
        CONST_TO_NAME(NODE_OP_ASGN_AND)
        CONST_TO_NAME(NODE_OP_ASGN_OR)
        CONST_TO_NAME(NODE_CALL)
        CONST_TO_NAME(NODE_FCALL)
        CONST_TO_NAME(NODE_VCALL)
        CONST_TO_NAME(NODE_SUPER)
        CONST_TO_NAME(NODE_ZSUPER)
        CONST_TO_NAME(NODE_ARRAY)
        CONST_TO_NAME(NODE_ZARRAY)
        CONST_TO_NAME(NODE_HASH)
        CONST_TO_NAME(NODE_RETURN)
        CONST_TO_NAME(NODE_YIELD)
        CONST_TO_NAME(NODE_LVAR)
        CONST_TO_NAME(NODE_DVAR)
        CONST_TO_NAME(NODE_GVAR)
        CONST_TO_NAME(NODE_IVAR)
        CONST_TO_NAME(NODE_CONST)
        CONST_TO_NAME(NODE_CVAR)
        CONST_TO_NAME(NODE_NTH_REF)
        CONST_TO_NAME(NODE_BACK_REF)
        CONST_TO_NAME(NODE_MATCH)
        CONST_TO_NAME(NODE_MATCH2)
        CONST_TO_NAME(NODE_MATCH3)
        CONST_TO_NAME(NODE_LIT)
        CONST_TO_NAME(NODE_STR)
        CONST_TO_NAME(NODE_DSTR)
        CONST_TO_NAME(NODE_XSTR)
        CONST_TO_NAME(NODE_DXSTR)
        CONST_TO_NAME(NODE_EVSTR)
        CONST_TO_NAME(NODE_DREGX)
        CONST_TO_NAME(NODE_DREGX_ONCE)
        CONST_TO_NAME(NODE_ARGS)
        CONST_TO_NAME(NODE_ARGSCAT)
        CONST_TO_NAME(NODE_ARGSPUSH)
        CONST_TO_NAME(NODE_SPLAT)
        CONST_TO_NAME(NODE_TO_ARY)
        CONST_TO_NAME(NODE_SVALUE)
        CONST_TO_NAME(NODE_BLOCK_ARG)
        CONST_TO_NAME(NODE_BLOCK_PASS)
        CONST_TO_NAME(NODE_DEFN)
        CONST_TO_NAME(NODE_DEFS)
        CONST_TO_NAME(NODE_ALIAS)
        CONST_TO_NAME(NODE_VALIAS)
        CONST_TO_NAME(NODE_UNDEF)
        CONST_TO_NAME(NODE_CLASS)
        CONST_TO_NAME(NODE_MODULE)
        CONST_TO_NAME(NODE_SCLASS)
        CONST_TO_NAME(NODE_COLON2)
        CONST_TO_NAME(NODE_COLON3)
        CONST_TO_NAME(NODE_CREF)
        CONST_TO_NAME(NODE_DOT2)
        CONST_TO_NAME(NODE_DOT3)
        CONST_TO_NAME(NODE_FLIP2)
        CONST_TO_NAME(NODE_FLIP3)
        CONST_TO_NAME(NODE_ATTRSET)
        CONST_TO_NAME(NODE_SELF)
        CONST_TO_NAME(NODE_NIL)
        CONST_TO_NAME(NODE_TRUE)
        CONST_TO_NAME(NODE_FALSE)
        CONST_TO_NAME(NODE_DEFINED)
        CONST_TO_NAME(NODE_NEWLINE)
        CONST_TO_NAME(NODE_POSTEXE)
        CONST_TO_NAME(NODE_ALLOCA)
        CONST_TO_NAME(NODE_DMETHOD)
        CONST_TO_NAME(NODE_BMETHOD)
        CONST_TO_NAME(NODE_MEMO)
        CONST_TO_NAME(NODE_IFUNC)
        CONST_TO_NAME(NODE_DSYM)
        CONST_TO_NAME(NODE_ATTRASGN)
        CONST_TO_NAME(NODE_LAST)
        default: return "____";
    }
}

static void
free_unused_heaps()
{
    int i, j;

    for (i = j = 1; j < heaps_used; i++) {
        if (heaps[i].limit == 0) {
            free(heaps[i].membase);
            free(heaps[i].marks);
            heaps_used--;
        }
        else {
            if (i != j) {
                heaps[j] = heaps[i];
            }
            j++;
        }
    }
}

void rb_gc_abort_threads(void);

static void
remembered_set_recycle()
{
    remembered_set_t *top = 0, *rem, *next;

    int recycled = 0;
    int kept = 0;
    rem = remembered_set_ptr;
    while (rem) {
        next = rem->next;
        if (rb_mark_table_contains((RVALUE *)rem->obj)) {
            top = rem;
            ++kept;
        }
        else {
            if (top) {
                top->next = next;
            }
            else {
                remembered_set_ptr = next;
            }
            rem->obj = 0;
            rem->next = remembered_set_freed;
            remembered_set_freed = rem;
            ++recycled;
        }
        rem = next;
    }
    GC_DEBUG_PRINTF("  Remembered set kept:           %8d\n", kept)
    GC_DEBUG_PRINTF("  Remembered set recycled:       %8d\n", recycled)
}

static void
gc_sweep(heaps_space_t *heaps_space)
{
    RVALUE *p, *pstart, *final_list;
    struct heaps_slot *heap;
    int i, deferred, type, new_heap_size, prev_sourcefiles_count;
    int lt = heaps_space->lifetime;

    /* individual heap counters */
    unsigned long free_slots, newly_freed_slots, finalized_slots, already_freed_slots, live_slots;

    /* heapspace total counters */
    unsigned long total_free_slots = 0;
#ifdef GC_DEBUG
    unsigned long total_newly_freed_slots = 0;
    unsigned long total_finalized_slots = 0;
    unsigned long total_already_freed_slots = 0;
    unsigned long total_live_slots = 0;
    int empty_heaps = 0;

    int prev_source_positions_count;
    int free_counts[OBJ_TYPE_COUNT];
    int live_counts[OBJ_TYPE_COUNT];
    const char *heaps_space_name;

    if (GC_DEBUG_ON) {
        heaps_space_name = lifetime_name[lt];
        if (lt == lifetime_longlife) {
            fprintf(gc_data_file, "  %s collection (after %d edens)\n", heaps_space_name, gc_eden_cycles_since_last_longlife);
            fprintf(gc_data_file, "  Objects moved to longlife: %8d\n", longlife_moved_objs_count);
            gc_eden_cycles_since_last_longlife = 0;
            longlife_moved_objs_count = 0;
        } else {
            fprintf(gc_data_file, "  %s collection\n", heaps_space_name);
        }
        MEMZERO(&free_counts, int, OBJ_TYPE_COUNT);
        MEMZERO(&live_counts, int, OBJ_TYPE_COUNT);
    }
#endif

    heaps_space->freelist = 0;
    final_list = deferred_final_list;
    deferred_final_list = 0;

#ifdef GC_DEBUG
    st_table *freed_objects_table, *live_objects_table;
    if (GC_DEBUG_ON && gc_debug_dump) {
        freed_objects_table = st_init_table_with_size(&source_positions_type, SOURCE_POS_INIT_TMP_SIZE);
        live_objects_table = st_init_table_with_size(&source_positions_type, SOURCE_POS_INIT_TMP_SIZE);
    }
#endif

    for (i = heaps_used - 1; i >= 0; i--) {
        heap = &heaps[i];
        if (heap->lifetime != lt) continue;

        RVALUE *free = heaps_space->freelist;
        RVALUE *final = final_list;

        finalized_slots = 0;
        newly_freed_slots = 0;
        already_freed_slots = 0;
        live_slots = 0;

        /* Add freed slots in reverse order, so that the first physical free slot is
            the head of the freelist. This is a feeble attempt to reduce fragmentation. */
        pstart = heap->slot;
        p = pstart + heap->limit;
        while (p-- > pstart) {
            type = BUILTIN_TYPE(p);
            if (!rb_mark_table_heap_contains(heap, p)) {
                if (p->as.basic.flags) {
#ifdef GC_DEBUG
                    if (GC_DEBUG_ON && gc_debug_dump) {
                        gc_debug_add_to_source_pos_table(freed_objects_table, p, type);
                    }
#endif
                    deferred = obj_free((VALUE)p);
                    if (deferred || ((FL_TEST(p, FL_FINALIZE)) && need_call_final)) {
                        /* This object has a finalizer, so don't free it right now, but do it later. */
                        finalized_slots++;
                        if (!deferred) {
                            p->as.free.flags = T_DEFERRED;
                            RDATA(p)->dfree = 0;
                        }
                        rb_mark_table_heap_add(heap, p); /* remain marked */
                        p->as.free.next = final_list;
                        final_list = p;
                    } else {
                        newly_freed_slots++;
#ifdef GC_DEBUG
                        if (GC_DEBUG_ON && type) free_counts[type]++;
#endif
                        push_freelist(heaps_space, p);
                    }
                } else {
                    already_freed_slots++;
                    push_freelist(heaps_space, p);
                }
#ifdef GC_DEBUG
            } else if (type == T_DEFERRED) {
                live_slots++;
                /* objects to be finalized */
                /* do nothing remain marked */
            } else {
                live_slots++;
                if (GC_DEBUG_ON) {
                    live_counts[type]++;
                    if (gc_debug_dump) {
                        gc_debug_add_to_source_pos_table(live_objects_table, p, type);
                    }
                }
#endif
            }
        }

        free_slots = already_freed_slots + newly_freed_slots + finalized_slots;
        total_free_slots += free_slots;
#ifdef GC_DEBUG
        total_already_freed_slots += already_freed_slots;
        total_newly_freed_slots += newly_freed_slots;
        total_finalized_slots += finalized_slots;
        total_live_slots += live_slots;
#endif

        if (free_slots == heap->limit) {
            /* Any unfragmented empty heaps? */
#ifdef GC_DEBUG
            empty_heaps++;
#endif
            if (gc_debug_stress ||
                /* Shrink longlife if it's too lazy */
                (lt == lifetime_longlife && (total_free_slots > heaps_space->heap_slots_total * longlife_laziness)) ||
                /* Shrink eden if there is a freeable heap and we are over our target size */
                (lt == lifetime_eden && (heaps_space->num_heaps > eden_heaps))) {
                GC_DEBUG_PRINTF("  %s heap freed (size %d)\n", heaps_space_name, heap->limit)
                RVALUE *pp;
                heaps_space->heap_slots_total -= heap->limit;
                heaps_space->num_heaps--;
                heap->limit = 0;
                heap->slotlimit = heap->slot;
                for (pp = final_list; pp != final; pp = pp->as.free.next) {
                    pp->as.free.flags |= FL_SINGLETON; /* freeing page mark */
                }
                heaps_space->freelist = free;   /* cancel this page from freelist */
            }
        }
    }

    if ((lt == lifetime_longlife &&
            /* Expand longlife if it's not lazy enough */
            (total_free_slots < heaps_space->heap_slots_total * longlife_laziness)) ||
        (lt == lifetime_eden &&
            /* Add one eden heap at a time (to reduce initial fragmentation) until we reach
                the target size */
            (heaps_space->num_heaps < eden_heaps))) {
          new_heap_size = add_heap(heaps_space);
          GC_DEBUG_PRINTF("  %s heap added (size %d)\n", heaps_space_name, new_heap_size)
#ifdef GC_DEBUG
          total_free_slots += new_heap_size;
#endif
    }

    if (lt == lifetime_longlife) {
        if (final_list) {
            deferred_final_list = final_list;
        }
        mark_source_filename(ruby_sourcefile);
        longlife_recent_allocations = 0;
        remembered_set_recycle();
    } else { /* lt == lifetime_eden */
        during_gc = 0;
        /* clear finalization list */
        if (final_list) {
            deferred_final_list = final_list;
            if (!rb_thread_critical) {
                rb_gc_finalize_deferred();
            } else {
                rb_thread_pending = 1;
            }
        }
        free_unused_heaps();
    }

#ifdef GC_DEBUG
    if (GC_DEBUG_ON) {
        fprintf(gc_data_file, "  %s heaps in heapspace:   %8d\n", heaps_space_name, heaps_space->num_heaps);
        fprintf(gc_data_file, "  %s empty heaps:          %8d\n", heaps_space_name, empty_heaps);
        fprintf(gc_data_file, "  %s total slots:          %8lu\n", heaps_space_name, total_live_slots + total_free_slots);
        fprintf(gc_data_file, "  %s already free slots:   %8lu\n", heaps_space_name, total_already_freed_slots);
        fprintf(gc_data_file, "  %s finalized free slots: %8lu\n", heaps_space_name, total_finalized_slots);
        fprintf(gc_data_file, "  %s live objects:         %8lu\n", heaps_space_name, total_live_slots);
        fprintf(gc_data_file, "  %s freed objects:        %8lu\n", heaps_space_name, total_newly_freed_slots);

        if (gc_debug_summary) {
            fprintf(gc_data_file, "  %s objects summary:\n    Type         Live    Freed\n",  heaps_space_name);

            for(i = 0; i < OBJ_TYPE_COUNT; i++) {
                if (free_counts[i] > 0 || live_counts[i] > 0) {
                    fprintf(gc_data_file, "    %-8s %8d %8d\n", obj_type(i), live_counts[i], free_counts[i]);
                }
            }
        }

        if (gc_debug_dump) {
            gc_debug_dump_source_pos_table(live_objects_table, lt, "live");
            gc_debug_dump_source_pos_table(freed_objects_table, lt, "freed");
            st_free_table(live_objects_table);
            st_free_table(freed_objects_table);
        }
    }
#endif

    if (lt == lifetime_eden) {
        prev_sourcefiles_count = source_filenames->num_entries;
#ifdef GC_DEBUG
        if (source_positions) {
            prev_source_positions_count = source_positions->num_entries;
            if (longlife_collection) {
                st_foreach(source_positions, sweep_source_pos, 0);
                GC_DEBUG_PRINTF("  Source position freed structs: %8d\n", prev_source_positions_count - source_positions->num_entries)
            }
            GC_DEBUG_PRINTF("  Source position live structs:  %8d\n", source_positions->num_entries)
        }
#endif
        if (longlife_collection) {
            st_foreach(source_filenames, sweep_source_filename, 0);
            GC_DEBUG_PRINTF("  Source filename freed strings: %8d\n", prev_sourcefiles_count - source_filenames->num_entries)
        }
       GC_DEBUG_PRINTF("  Source filename live strings:  %8d\n", source_filenames->num_entries)
    }
}

void
rb_gc_force_recycle(p)
    VALUE p;
{
    rb_mark_table_remove((RVALUE *) p);
    add_to_correct_freelist(RANY(p));
}

static inline void
make_deferred(p)
    RVALUE *p;
{
    p->as.basic.flags = (p->as.basic.flags & ~T_MASK) | T_DEFERRED;
}

static int
obj_free(obj)
    VALUE obj;
{
    switch (BUILTIN_TYPE(obj)) {
      case T_NIL:
      case T_FIXNUM:
      case T_TRUE:
      case T_FALSE:
        rb_bug("obj_free() called for broken object");
        break;
    }

    if (FL_TEST(obj, FL_EXIVAR)) {
        rb_free_generic_ivar((VALUE)obj);
    }

    switch (BUILTIN_TYPE(obj)) {
      case T_OBJECT:
        if (RANY(obj)->as.object.iv_tbl) {
            st_free_table(RANY(obj)->as.object.iv_tbl);
        }
        break;
      case T_MODULE:
      case T_CLASS:
        rb_clear_cache_by_class((VALUE)obj);
        st_free_table(RANY(obj)->as.klass.m_tbl);
        if (RANY(obj)->as.object.iv_tbl) {
            st_free_table(RANY(obj)->as.object.iv_tbl);
        }
        break;
      case T_STRING:
        if (RANY(obj)->as.string.ptr && !FL_TEST(obj, ELTS_SHARED)) {
            RUBY_CRITICAL(free(RANY(obj)->as.string.ptr));
        }
        break;
      case T_ARRAY:
        if (RANY(obj)->as.array.ptr && !FL_TEST(obj, ELTS_SHARED)) {
            RUBY_CRITICAL(free(RANY(obj)->as.array.ptr));
        }
        break;
      case T_HASH:
        if (RANY(obj)->as.hash.tbl) {
            st_free_table(RANY(obj)->as.hash.tbl);
        }
        break;
      case T_REGEXP:
        if (RANY(obj)->as.regexp.ptr) {
            re_free_pattern(RANY(obj)->as.regexp.ptr);
        }
        if (RANY(obj)->as.regexp.str) {
            RUBY_CRITICAL(free(RANY(obj)->as.regexp.str));
        }
        break;
      case T_DATA:
        if (DATA_PTR(obj)) {
            if ((long)RANY(obj)->as.data.dfree == -1) {
                RUBY_CRITICAL(free(DATA_PTR(obj)));
            }
            else if (RANY(obj)->as.data.dfree) {
                make_deferred(RANY(obj));
                return 1;
            }
        }
        break;
      case T_MATCH:
        if (RANY(obj)->as.match.regs) {
            re_free_registers(RANY(obj)->as.match.regs);
            RUBY_CRITICAL(free(RANY(obj)->as.match.regs));
        }
        break;
      case T_FILE:
        if (RANY(obj)->as.file.fptr) {
            struct rb_io_t *fptr = RANY(obj)->as.file.fptr;
            make_deferred(RANY(obj));
            RDATA(obj)->dfree = (void (*)(void*))rb_io_fptr_finalize;
            RDATA(obj)->data = fptr;
            return 1;
        }
        break;
      case T_ICLASS:
        /* iClass shares table with the module */
        break;

      case T_FLOAT:
      case T_VARMAP:
      case T_BLKTAG:
        break;

      case T_BIGNUM:
        if (RANY(obj)->as.bignum.digits) {
            RUBY_CRITICAL(free(RANY(obj)->as.bignum.digits));
        }
        break;
      case T_NODE:
        switch (nd_type(obj)) {
          case NODE_SCOPE:
            if (RANY(obj)->as.node.u1.tbl) {
                RUBY_CRITICAL(free(RANY(obj)->as.node.u1.tbl));
            }
            break;
          case NODE_ALLOCA:
            RUBY_CRITICAL(free(RANY(obj)->as.node.u1.node));
            break;
        }
        break;                  /* no need to free iv_tbl */

      case T_SCOPE:
        if (RANY(obj)->as.scope.local_vars &&
            RANY(obj)->as.scope.flags != SCOPE_ALLOCA) {
            VALUE *vars = RANY(obj)->as.scope.local_vars-1;
            if (!(RANY(obj)->as.scope.flags & SCOPE_CLONE) && vars[0] == 0)
                RUBY_CRITICAL(free(RANY(obj)->as.scope.local_tbl));
            if ((RANY(obj)->as.scope.flags & (SCOPE_MALLOC|SCOPE_CLONE)) == SCOPE_MALLOC)
                RUBY_CRITICAL(free(vars));
        }
        break;

      case T_STRUCT:
        if (RANY(obj)->as.rstruct.ptr) {
            RUBY_CRITICAL(free(RANY(obj)->as.rstruct.ptr));
        }
        break;

      default:
        rb_bug("gc_sweep(): unknown data type 0x%lx(0x%lx)",
               RANY(obj)->as.basic.flags & T_MASK, obj);
    }

    return 0;
}

void
rb_gc_mark_frame(frame)
    struct FRAME *frame;
{
    rb_gc_mark((VALUE)frame->node);
#ifdef GC_DEBUG
    mark_source_pos(frame->source_pos);
#endif
}

#ifdef __GNUC__
#if defined(__human68k__) || defined(DJGPP)
#undef rb_setjmp
#undef rb_jmp_buf
#if defined(__human68k__)
typedef unsigned long rb_jmp_buf[8];
__asm__ (".even\n\
_rb_setjmp:\n\
        move.l  4(sp),a0\n\
        movem.l d3-d7/a3-a5,(a0)\n\
        moveq.l #0,d0\n\
        rts");
#else
#if defined(DJGPP)
typedef unsigned long rb_jmp_buf[6];
__asm__ (".align 4\n\
_rb_setjmp:\n\
        pushl   %ebp\n\
        movl    %esp,%ebp\n\
        movl    8(%ebp),%ebp\n\
        movl    %eax,(%ebp)\n\
        movl    %ebx,4(%ebp)\n\
        movl    %ecx,8(%ebp)\n\
        movl    %edx,12(%ebp)\n\
        movl    %esi,16(%ebp)\n\
        movl    %edi,20(%ebp)\n\
        popl    %ebp\n\
        xorl    %eax,%eax\n\
        ret");
#endif
#endif
int rb_setjmp (rb_jmp_buf);
#endif /* __human68k__ or DJGPP */
#endif /* __GNUC__ */

static int
add_entry_to_remembered_set(key, value)
    ID key;
    VALUE value;
{
    rb_gc_write_barrier(value);
    return ST_CONTINUE;
}

void
add_table_to_remembered_set(tbl)
    st_table *tbl;
{
    if (!tbl) return;
    st_foreach(tbl, add_entry_to_remembered_set, 0);
}

static int
add_keyvalue_to_remembered_set(key, value)
    VALUE key;
    VALUE value;
{
    rb_gc_write_barrier(key);
    rb_gc_write_barrier(value);
    return ST_CONTINUE;
}

static void
add_hash_to_remembered_set(tbl)
    st_table *tbl;
{
    if (!tbl) return;
    st_foreach(tbl, add_keyvalue_to_remembered_set, 0);
}

static void
add_array_elements_to_remembered_set(x, n)
    VALUE *x;
    size_t n;
{
    VALUE v;
    while (n--) {
        v = *x;
        if (is_pointer_to_heap((void *)v)) {
            rb_gc_write_barrier(v);
        }
        x++;
    }
}

static void
add_children_to_remembered_set(ptr)
    VALUE ptr;
{
    RVALUE *obj = RANY(ptr);

    if (FL_TEST(obj, FL_EXIVAR)) {
        add_generic_ivar_to_remembered_set(ptr);
    }

    switch (obj->as.basic.flags & T_MASK) {
      case T_NIL:
      case T_FIXNUM:
        rb_bug("add_children_to_remembered_set() called for broken object");
        break;

      case T_NODE:
        switch (nd_type(obj)) {
          case NODE_IF:         /* 1,2,3 */
          case NODE_FOR:
          case NODE_ITER:
          case NODE_CREF:
          case NODE_WHEN:
          case NODE_MASGN:
          case NODE_RESCUE:
          case NODE_RESBODY:
          case NODE_CLASS:
            rb_gc_write_barrier((VALUE)obj->as.node.u2.node);
            /* fall through */
          case NODE_BLOCK:      /* 1,3 */
          case NODE_ARRAY:
          case NODE_DSTR:
          case NODE_DXSTR:
          case NODE_DREGX:
          case NODE_DREGX_ONCE:
          case NODE_FBODY:
          case NODE_ENSURE:
          case NODE_CALL:
          case NODE_DEFS:
          case NODE_OP_ASGN1:
            rb_gc_write_barrier((VALUE)obj->as.node.u1.node);
            /* fall through */
          case NODE_SUPER:      /* 3 */
          case NODE_FCALL:
          case NODE_DEFN:
          case NODE_NEWLINE:
            rb_gc_write_barrier((VALUE)obj->as.node.u3.node);
            break;

          case NODE_WHILE:      /* 1,2 */
          case NODE_UNTIL:
          case NODE_AND:
          case NODE_OR:
          case NODE_CASE:
          case NODE_SCLASS:
          case NODE_DOT2:
          case NODE_DOT3:
          case NODE_FLIP2:
          case NODE_FLIP3:
          case NODE_MATCH2:
          case NODE_MATCH3:
          case NODE_OP_ASGN_OR:
          case NODE_OP_ASGN_AND:
          case NODE_MODULE:
          case NODE_ALIAS:
          case NODE_VALIAS:
          case NODE_ARGS:
            rb_gc_write_barrier((VALUE)obj->as.node.u1.node);
            /* fall through */
          case NODE_METHOD:     /* 2 */
          case NODE_NOT:
          case NODE_GASGN:
          case NODE_LASGN:
          case NODE_DASGN:
          case NODE_DASGN_CURR:
          case NODE_IASGN:
          case NODE_CVDECL:
          case NODE_CVASGN:
          case NODE_COLON3:
          case NODE_OPT_N:
          case NODE_EVSTR:
          case NODE_UNDEF:
            rb_gc_write_barrier((VALUE)obj->as.node.u2.node);
            break;

          case NODE_HASH:       /* 1 */
          case NODE_LIT:
          case NODE_STR:
          case NODE_XSTR:
          case NODE_DEFINED:
          case NODE_MATCH:
          case NODE_RETURN:
          case NODE_BREAK:
          case NODE_NEXT:
          case NODE_YIELD:
          case NODE_COLON2:
          case NODE_SPLAT:
          case NODE_TO_ARY:
          case NODE_SVALUE:
            rb_gc_write_barrier((VALUE)obj->as.node.u1.node);
            break;

          case NODE_SCOPE:      /* 2,3 */
          case NODE_BLOCK_PASS:
          case NODE_CDECL:
            rb_gc_write_barrier((VALUE)obj->as.node.u3.node);
            rb_gc_write_barrier((VALUE)obj->as.node.u2.node);
            break;

          case NODE_ZARRAY:     /* - */
          case NODE_ZSUPER:
          case NODE_CFUNC:
          case NODE_VCALL:
          case NODE_GVAR:
          case NODE_LVAR:
          case NODE_DVAR:
          case NODE_IVAR:
          case NODE_CVAR:
          case NODE_NTH_REF:
          case NODE_BACK_REF:
          case NODE_REDO:
          case NODE_RETRY:
          case NODE_SELF:
          case NODE_NIL:
          case NODE_TRUE:
          case NODE_FALSE:
          case NODE_ATTRSET:
          case NODE_BLOCK_ARG:
          case NODE_POSTEXE:
            break;
          case NODE_ALLOCA:
            add_array_elements_to_remembered_set((VALUE*)obj->as.node.u1.value,
                                 obj->as.node.u3.cnt);
            rb_gc_write_barrier((VALUE)obj->as.node.u2.node);
            break;

          default:              /* unlisted NODE */
            if (is_pointer_to_heap(obj->as.node.u1.node)) {
                rb_gc_write_barrier((VALUE)obj->as.node.u1.node);
            }
            if (is_pointer_to_heap(obj->as.node.u2.node)) {
                rb_gc_write_barrier((VALUE)obj->as.node.u2.node);
            }
            if (is_pointer_to_heap(obj->as.node.u3.node)) {
                rb_gc_write_barrier((VALUE)obj->as.node.u3.node);
            }
        }
        return; /* no need to mark class. */
    }

    rb_gc_write_barrier(obj->as.basic.klass);
    switch (obj->as.basic.flags & T_MASK) {
      case T_ICLASS:
      case T_CLASS:
      case T_MODULE:
        add_table_to_remembered_set(obj->as.klass.m_tbl);
        add_table_to_remembered_set(obj->as.klass.iv_tbl);
        rb_gc_write_barrier(obj->as.klass.super);
        break;

      case T_ARRAY:
        if (FL_TEST(obj, ELTS_SHARED)) {
            rb_gc_write_barrier(obj->as.array.aux.shared);
        }
        else {
            VALUE *ptr = obj->as.array.ptr;
            VALUE *pend = ptr + obj->as.array.len;
            while (ptr < pend) {
                rb_gc_write_barrier(*ptr++);
            }
        }
        break;

      case T_HASH:
        add_hash_to_remembered_set(obj->as.hash.tbl);
        rb_gc_write_barrier(obj->as.hash.ifnone);
        break;

      case T_STRING:
#define STR_ASSOC FL_USER3   /* copied from string.c */
        if (FL_TEST(obj, ELTS_SHARED|STR_ASSOC)) {
            rb_gc_write_barrier(obj->as.string.aux.shared);
        }
        break;

      case T_DATA:
        rb_bug("add_children_to_remembered_set() encountered T_DATA 0x%lx", obj);
        break;

      case T_OBJECT:
        add_table_to_remembered_set(obj->as.object.iv_tbl);
        break;

      case T_FILE:
      case T_REGEXP:
      case T_FLOAT:
      case T_BIGNUM:
      case T_BLKTAG:
        break;

      case T_MATCH:
        if (obj->as.match.str) {
            rb_gc_write_barrier(obj->as.match.str);
        }
        break;

      case T_VARMAP:
        rb_gc_write_barrier(obj->as.varmap.val);
        rb_gc_write_barrier((VALUE)obj->as.varmap.next);
        break;

      case T_SCOPE:
        if (obj->as.scope.local_vars && (obj->as.scope.flags & SCOPE_MALLOC)) {
            int n = obj->as.scope.local_tbl[0]+1;
            VALUE *vars = &obj->as.scope.local_vars[-1];

            while (n--) {
                rb_gc_write_barrier(*vars++);
            }
        }
        break;

      case T_STRUCT:
        {
            VALUE *ptr = obj->as.rstruct.ptr;
            VALUE *pend = ptr + obj->as.rstruct.len;
            while (ptr < pend)
               rb_gc_write_barrier(*ptr++);
        }
        break;

      default:
        rb_bug("add_children_to_remembered_set(): unknown data type 0x%lx(0x%lx) %s",
               obj->as.basic.flags & T_MASK, obj,
               is_pointer_to_heap(obj) ? "corrupted object" : "non object");
    }
}

static void
rb_gc_recycle_longlife_recent_allocations_set()
{
    longlife_recent_allocations_set_t *drem, *next;
    int seen = 0;

    if (longlife_recent_allocations_set_ptr) {
        drem = longlife_recent_allocations_set_ptr;
        while (drem) {
            next = drem->next;
            seen += 1;
            if (drem->obj->as.basic.flags) {
                add_children_to_remembered_set((VALUE)(drem->obj));
            }
            drem->obj = 0;
            if (next == 0) {
                drem->next = longlife_recent_allocations_set_freed;
            }
            drem = next;
        }

        longlife_recent_allocations += seen;
        longlife_recent_allocations_set_freed = longlife_recent_allocations_set_ptr;
        longlife_recent_allocations_set_ptr = 0;
    }

    GC_DEBUG_PRINTF("  Added %d new longlife allocations to remembered set\n", seen)
}

static void
rb_gc_mark_remembered_set()
{
    remembered_set_t *rem = remembered_set_ptr;
    while (rem) {
        rb_gc_mark((VALUE)rem->obj);
        rem = rem->next;
    }
}

#ifdef GC_DEBUG
static GC_TIME_TYPE microseconds(struct timeval t) {
    return t.tv_sec * 1000000 + t.tv_usec;
}

static GC_TIME_TYPE timediff_microseconds(struct timeval later, struct timeval earlier) {
    GC_TIME_TYPE diff = microseconds(later) - microseconds(earlier);
    return diff > 0 ? diff : 0;
}
#endif

static void
garbage_collect_0(VALUE *top_frame)
{
    struct gc_list *list;
    struct FRAME * frame;
    SET_STACK_END;

#ifdef HAVE_NATIVETHREAD
    if (!is_ruby_native_thread()) {
        rb_bug("cross-thread violation on rb_gc()");
    }
#endif
    if (dont_gc || during_gc || ruby_in_compile) {
        add_heap_if_needed(&eden_heaps_space);
        GC_DEBUG_PRINTF("  Skipped due to reason: %s=1\n",
            dont_gc ? "dont_gc" : (during_gc ? "during_gc" : "ruby_in_compile"))
        return;
    }

    during_gc++;

#ifdef GC_DEBUG
    struct rusage ru1, ru2;

    if (GC_DEBUG_ON) {
        gc_eden_cycles_since_last_longlife++;
        getrusage(RUSAGE_SELF, &ru1);
    }
#endif

    /*** Schedule optional longlife GC based on allocation rate ***/

    if (longlife_recent_allocations > longlife_heaps_space.heap_slots_total * longlife_laziness) {
        longlife_collection = Qtrue;
    }

    /* Add any new longlife allocations to the remembered set */
    rb_gc_recycle_longlife_recent_allocations_set();

    /*** Mark phase ***/

    gc_stack_limit = __stack_grow(STACK_END, GC_LEVEL_MAX);
    rb_mark_table_prepare();
    init_mark_stack();

    rb_mark_table_reset(lifetime_eden);
    if (longlife_collection) {
        rb_mark_table_reset(lifetime_longlife);
    } else {
        // Mark remembered references from longlife to eden
        rb_gc_mark_remembered_set();
    }

    /* mark frame stack */
    if (rb_curr_thread == rb_main_thread) {
        frame = ruby_frame;
    } else {
        frame = rb_main_thread->frame;
    } for (; frame; frame = frame->prev) {
        rb_gc_mark_frame(frame);
        if (frame->tmp) {
            struct FRAME *tmp = frame->tmp;
            while (tmp) {
                rb_gc_mark_frame(tmp);
                tmp = tmp->prev;
            }
        }
    }

    if (rb_curr_thread == rb_main_thread) {
        rb_gc_mark((VALUE)ruby_current_node);
        rb_gc_mark((VALUE)ruby_scope);
        rb_gc_mark((VALUE)ruby_dyna_vars);
    } else {
        rb_gc_mark((VALUE)rb_main_thread->node);
        rb_gc_mark((VALUE)rb_main_thread->scope);
        rb_gc_mark((VALUE)rb_main_thread->dyna_vars);

        /* scan the current thread's stack */
        rb_gc_mark_locations(top_frame, rb_curr_thread->stk_base);
    }

    if (finalizer_table) {
        mark_tbl(finalizer_table);
    }

    /* If this is not the main thread, we need to scan the C stack, so
     * set top_frame to the end of the C stack.
     */
    if (rb_curr_thread != rb_main_thread) {
        top_frame = rb_main_thread->stk_pos;
    }

#if STACK_GROW_DIRECTION < 0
    rb_gc_mark_locations(top_frame, rb_gc_stack_start);
#elif STACK_GROW_DIRECTION > 0
    rb_gc_mark_locations(rb_gc_stack_start, top_frame + 1);
#else
    if (rb_gc_stack_grow_direction < 0) {
        rb_gc_mark_locations(top_frame, rb_gc_stack_start);
    } else {
        rb_gc_mark_locations(rb_gc_stack_start, top_frame + 1);
    }
#endif
#ifdef __ia64
    /* mark backing store (flushed register window on the stack) */
    /* the basic idea from guile GC code                         */
    rb_gc_mark_locations(rb_gc_register_stack_start, (VALUE*)rb_ia64_bsp());
#endif
#if defined(__human68k__) || defined(__mc68000__)
    rb_gc_mark_locations((VALUE*)((char*)STACK_END + 2),
                         (VALUE*)((char*)rb_gc_stack_start + 2));
#endif

    rb_gc_mark_threads();

    /* mark protected global variables */
    for (list = global_List; list; list = list->next) {
        rb_gc_mark_maybe(*list->varptr);
    }
    rb_mark_end_proc();
    rb_gc_mark_global_tbl();

    rb_mark_tbl(rb_class_tbl);
    rb_gc_mark_trap_list();

    /* mark generic instance variables for special constants */
    rb_mark_generic_ivar_tbl();

    rb_gc_mark_parser();

    /* gc_mark objects whose marking are not completed*/
    do {
        while (!MARK_STACK_EMPTY) {
            if (mark_stack_overflow){
                gc_mark_all();
            }
            else {
                gc_mark_rest();
            }
        }
        rb_gc_abort_threads();
    } while (!MARK_STACK_EMPTY);

    /*** Sweep phase ***/

    if (longlife_collection) {
        gc_sweep(&longlife_heaps_space);
    }
    gc_sweep(&eden_heaps_space);

    if (longlife_collection) {
      gc_longlife_cycles++;
      longlife_collection = Qfalse;
    } else {
      gc_cycles++;
    }

#ifdef GC_DEBUG
    if (GC_DEBUG_ON) {
        GC_TIME_TYPE musecs_used_user;
        GC_TIME_TYPE musecs_used_system;
        GC_TIME_TYPE musecs_used;
        getrusage(RUSAGE_SELF, &ru2);
        musecs_used_user = timediff_microseconds(ru2.ru_utime, ru1.ru_utime);
        musecs_used_system = timediff_microseconds(ru2.ru_stime, ru1.ru_stime);
        musecs_used = musecs_used_user + musecs_used_system;

        fprintf(gc_data_file, "  Garbage collection finished: %llu usec (user: %llu, system: %llu)\n",
            musecs_used, musecs_used_user, musecs_used_system);
    }
#endif
}

static void
garbage_collect(const char* reason)
{
    jmp_buf save_regs_gc_mark;
    VALUE *top;
    FLUSH_REGISTER_WINDOWS;
    /* This assumes that all registers are saved into the jmp_buf (and stack) */
    rb_setjmp(save_regs_gc_mark);
    top = __sp();

    GC_DEBUG_PRINTF("*** Garbage collection (%s) ***\n", reason)

#if STACK_WIPE_SITES & 0x400
# ifdef nativeAllocA
    if ((!rb_main_thread || rb_curr_thread == rb_main_thread) && __stack_past (top, stack_limit)) {
        /* allocate a large frame to ensure app stack cannot grow into GC stack */
        (volatile void*) nativeAllocA(__stack_depth((void*)stack_limit,(void*)top));
    }
    garbage_collect_0(top);
# else /* no native alloca() available */
    garbage_collect_0(top);
    if (rb_curr_thread) {
        VALUE *paddedLimit = __stack_grow(gc_stack_limit, GC_STACK_PAD);
        if (__stack_past(rb_curr_thread->gc_stack_end, paddedLimit))
            rb_curr_thread->gc_stack_end = paddedLimit;
    }
    rb_gc_wipe_stack();  /* wipe the whole stack area reserved for this gc */
# endif
#else
    garbage_collect_0(top);
#endif
}

void
rb_gc()
{
    garbage_collect("explicitly called");
    rb_gc_finalize_deferred();
}

/*
 *  call-seq:
 *     GC.start                     => nil
 *     gc.garbage_collect           => nil
 *     ObjectSpace.garbage_collect  => nil
 *
 *  Initiates garbage collection, unless manually disabled.
 *
 */

VALUE
rb_gc_start()
{
    longlife_collection = Qtrue;
    rb_gc();
    return Qnil;
}


int
rb_gc_is_thread_marked(the_thread)
    VALUE the_thread;
{
    if (FL_ABLE(the_thread)) {
        return rb_mark_table_contains((RVALUE *) the_thread);
    } else {
        return 0;
    }
}

void
ruby_set_stack_size(size)
    size_t size;
{
#ifndef STACK_LEVEL_MAX
    STACK_LEVEL_MAX = size / sizeof(VALUE);
#endif
    stack_limit = __stack_grow(rb_gc_stack_start, STACK_LEVEL_MAX-GC_STACK_MAX);
}

static void
set_stack_size(void)
{
#ifdef HAVE_GETRLIMIT
  struct rlimit rlim;
  if (getrlimit(RLIMIT_STACK, &rlim) == 0) {
    if (rlim.rlim_cur > 0 && rlim.rlim_cur != RLIM_INFINITY) {
      size_t maxStackBytes = rlim.rlim_cur;
      if (rlim.rlim_cur != maxStackBytes)
        maxStackBytes = -1;
      {
        size_t space = maxStackBytes/5;
        if (space > 1024*1024) space = 1024*1024;
#ifdef __FreeBSD__
        /* For some reason we can't use more than 4 MB of stack on
        * FreeBSD even if getrlimit() reports a much higher amount.
        */
        if (maxStackBytes > 4 * 1024 * 1024)
            maxStackBytes = 4 * 1024 * 1024;
#endif
        ruby_set_stack_size(maxStackBytes - space);
        return;
      }
    }
  }
#endif
  ruby_set_stack_size(STACK_LEVEL_MAX*sizeof(VALUE));
}

void
Init_stack(addr)
    VALUE *addr;
{
#ifdef __ia64
    if (rb_gc_register_stack_start == 0) {
# if defined(__FreeBSD__)
        /*
         * FreeBSD/ia64 currently does not have a way for a process to get the
         * base address for the RSE backing store, so hardcode it.
         */
        rb_gc_register_stack_start = (4ULL<<61);
# elif defined(HAVE___LIBC_IA64_REGISTER_BACKING_STORE_BASE)
#  pragma weak __libc_ia64_register_backing_store_base
        extern unsigned long __libc_ia64_register_backing_store_base;
        rb_gc_register_stack_start = (VALUE*)__libc_ia64_register_backing_store_base;
# endif
    }
    {
        VALUE *bsp = (VALUE*)rb_ia64_bsp();
        if (rb_gc_register_stack_start == 0 ||
            bsp < rb_gc_register_stack_start) {
            rb_gc_register_stack_start = bsp;
        }
    }
#endif
#if defined(_WIN32) || defined(__CYGWIN__)
    MEMORY_BASIC_INFORMATION m;
    memset(&m, 0, sizeof(m));
    VirtualQuery(&m, &m, sizeof(m));
    rb_gc_stack_start =
        STACK_UPPER((VALUE *)m.BaseAddress,
                    (VALUE *)((char *)m.BaseAddress + m.RegionSize) - 1);
#elif defined(STACK_END_ADDRESS)
    {
        extern void *STACK_END_ADDRESS;
        rb_gc_stack_start = STACK_END_ADDRESS;
    }
#else
    if (!addr) addr = (void *)&addr;
    STACK_UPPER(addr, ++addr);
    if (rb_gc_stack_start) {
        if (STACK_UPPER(rb_gc_stack_start > addr,
                        rb_gc_stack_start < addr))
            rb_gc_stack_start = addr;
        return;
    }
    rb_gc_stack_start = addr;
#endif
    set_stack_size();
}

void ruby_init_stack(VALUE *addr
#ifdef __ia64
    , void *bsp
#endif
    )
{
    if (!rb_gc_stack_start ||
        STACK_UPPER(rb_gc_stack_start > addr,
                    rb_gc_stack_start < addr)) {
        rb_gc_stack_start = addr;
    }
#ifdef __ia64
    if (!rb_gc_register_stack_start ||
        (VALUE*)bsp < rb_gc_register_stack_start) {
        rb_gc_register_stack_start = (VALUE*)bsp;
    }
#endif
#ifdef HAVE_GETRLIMIT
    set_stack_size();
#elif defined _WIN32
    {
        MEMORY_BASIC_INFORMATION mi;
        DWORD size;
        DWORD space;

        if (VirtualQuery(&mi, &mi, sizeof(mi))) {
            size = (char *)mi.BaseAddress - (char *)mi.AllocationBase;
            space = size / 5;
            if (space > 1024*1024) space = 1024*1024;
            ruby_set_stack_size(size - space);
        }
    }
#endif
}

static void init_heaps_space(heaps_space_t* heaps_space, enum lifetime lifetime)
{
    heaps_space->heap_slots_total = 0;
    heaps_space->lifetime = lifetime;
}
/*
 * Document-class: ObjectSpace
 *
 *  The <code>ObjectSpace</code> module contains a number of routines
 *  that interact with the garbage collection facility and allow you to
 *  traverse all living objects with an iterator.
 *
 *  <code>ObjectSpace</code> also provides support for object
 *  finalizers, procs that will be called when a specific object is
 *  about to be destroyed by garbage collection.
 *
 *     include ObjectSpace
 *
 *
 *     a = "A"
 *     b = "B"
 *     c = "C"
 *
 *
 *     define_finalizer(a, proc {|id| puts "Finalizer one on #{id}" })
 *     define_finalizer(a, proc {|id| puts "Finalizer two on #{id}" })
 *     define_finalizer(b, proc {|id| puts "Finalizer three on #{id}" })
 *
 *  <em>produces:</em>
 *
 *     Finalizer three on 537763470
 *     Finalizer one on 537763480
 *     Finalizer two on 537763480
 *
 */

void
Init_heap()
{
    int new_heap_size;
    rb_mark_table_init();
    if (!rb_gc_stack_start) {
        Init_stack(0);
    }

    /* Need to set_gc_parameters() before heap initialization. */
    set_gc_parameters();

    init_heaps_space(&eden_heaps_space, lifetime_eden);
    new_heap_size = add_heap(&eden_heaps_space);
    GC_DEBUG_PRINTF("*** Eden heap added (initialization) (size %d) ***\n", new_heap_size)

    init_heaps_space(&longlife_heaps_space, lifetime_longlife);
    new_heap_size = add_heap(&longlife_heaps_space);
    GC_DEBUG_PRINTF("*** Longlife heap added (initialization) (size %d) ***\n", new_heap_size)
}

static VALUE
os_obj_of(of)
    VALUE of;
{
    int i;
    int n = 0;
    volatile VALUE v;

    for (i = 0; i < heaps_used; i++) {
        RVALUE *p, *pend;

        p = heaps[i].slot; pend = p + heaps[i].limit;
        for (;p < pend; p++) {
            if (p->as.basic.flags) {
                switch (BUILTIN_TYPE(p)) {
                  case T_NONE:
                  case T_ICLASS:
                  case T_VARMAP:
                  case T_SCOPE:
                  case T_NODE:
                  case T_DEFERRED:
                    continue;
                  case T_CLASS:
                    if (FL_TEST(p, FL_SINGLETON)) continue;
                  default:
                    if (!p->as.basic.klass) continue;
                    v = (VALUE)p;
                    if (!of || rb_obj_is_kind_of(v, of)) {
                        rb_yield(v);
                        n++;
                    }
                }
            }
        }
    }

    return INT2FIX(n);
}

/*
 *  call-seq:
 *     ObjectSpace.each_object([module]) {|obj| ... } => fixnum
 *
 *  Calls the block once for each living, nonimmediate object in this
 *  Ruby process. If <i>module</i> is specified, calls the block
 *  for only those classes or modules that match (or are a subclass of)
 *  <i>module</i>. Returns the number of objects found. Immediate
 *  objects (<code>Fixnum</code>s, <code>Symbol</code>s
 *  <code>true</code>, <code>false</code>, and <code>nil</code>) are
 *  never returned. In the example below, <code>each_object</code>
 *  returns both the numbers we defined and several constants defined in
 *  the <code>Math</code> module.
 *
 *     a = 102.7
 *     b = 95       # Won't be returned
 *     c = 12345678987654321
 *     count = ObjectSpace.each_object(Numeric) {|x| p x }
 *     puts "Total count: #{count}"
 *
 *  <em>produces:</em>
 *
 *     12345678987654321
 *     102.7
 *     2.71828182845905
 *     3.14159265358979
 *     2.22044604925031e-16
 *     1.7976931348623157e+308
 *     2.2250738585072e-308
 *     Total count: 7
 *
 */

static VALUE
os_each_obj(argc, argv, os)
    int argc;
    VALUE *argv;
    VALUE os;
{
    VALUE of;

    rb_secure(4);
    if (argc == 0) {
        of = 0;
    }
    else {
        rb_scan_args(argc, argv, "01", &of);
    }
    RETURN_ENUMERATOR(os, 1, &of);
    return os_obj_of(of);
}

static VALUE finalizers;

/* deprecated
 */

static VALUE
add_final(os, block)
    VALUE os, block;
{
    rb_warn("ObjectSpace::add_finalizer is deprecated; use define_finalizer");
    if (!rb_respond_to(block, rb_intern("call"))) {
        rb_raise(rb_eArgError, "wrong type argument %s (should be callable)",
                 rb_obj_classname(block));
    }
    rb_ary_push(finalizers, block);
    return block;
}

/*
 * deprecated
 */
static VALUE
rm_final(os, block)
    VALUE os, block;
{
    rb_warn("ObjectSpace::remove_finalizer is deprecated; use undefine_finalizer");
    rb_ary_delete(finalizers, block);
    return block;
}

/*
 * deprecated
 */
static VALUE
finals()
{
    rb_warn("ObjectSpace::finalizers is deprecated");
    return finalizers;
}

/*
 * deprecated
 */

static VALUE
call_final(os, obj)
    VALUE os, obj;
{
    rb_warn("ObjectSpace::call_finalizer is deprecated; use define_finalizer");
    need_call_final = 1;
    FL_SET(obj, FL_FINALIZE);
    return obj;
}

/*
 *  call-seq:
 *     ObjectSpace.undefine_finalizer(obj)
 *
 *  Removes all finalizers for <i>obj</i>.
 *
 */

static VALUE
undefine_final(os, obj)
    VALUE os, obj;
{
    if (finalizer_table) {
        st_delete(finalizer_table, (st_data_t*)&obj, 0);
    }
    return obj;
}

/*
 *  call-seq:
 *     ObjectSpace.define_finalizer(obj, aProc=proc())
 *
 *  Adds <i>aProc</i> as a finalizer, to be called after <i>obj</i>
 *  was destroyed.
 *
 */

static VALUE
define_final(argc, argv, os)
    int argc;
    VALUE *argv;
    VALUE os;
{
    VALUE obj, block, table;

    rb_scan_args(argc, argv, "11", &obj, &block);
    if (argc == 1) {
        block = rb_block_proc();
    }
    else if (!rb_respond_to(block, rb_intern("call"))) {
        rb_raise(rb_eArgError, "wrong type argument %s (should be callable)",
                 rb_obj_classname(block));
    }
    need_call_final = 1;
    if (!FL_ABLE(obj)) {
        rb_raise(rb_eArgError, "cannot define finalizer for %s",
                 rb_obj_classname(obj));
    }
    RBASIC(obj)->flags |= FL_FINALIZE;

    block = rb_ary_new3(2, INT2FIX(ruby_safe_level), block);
    OBJ_FREEZE(block);

    if (!finalizer_table) {
        finalizer_table = st_init_numtable();
    }
    if (st_lookup(finalizer_table, obj, &table)) {
        rb_ary_push(table, block);
    }
    else {
        table = rb_ary_new3(1, block);
        RBASIC(table)->klass = 0;
        st_add_direct(finalizer_table, obj, table);
    }
    return block;
}

void
rb_gc_copy_finalizer(dest, obj)
    VALUE dest, obj;
{
    VALUE table;

    if (!finalizer_table) return;
    if (!FL_TEST(obj, FL_FINALIZE)) return;
    if (st_lookup(finalizer_table, obj, &table)) {
        st_insert(finalizer_table, dest, table);
    }
    RBASIC(dest)->flags |= FL_FINALIZE;
}

static VALUE
run_single_final(args)
    VALUE *args;
{
    rb_eval_cmd(args[0], args[1], (int)args[2]);
    return Qnil;
}

static void
run_final(obj)
    VALUE obj;
{
    long i;
    int status, critical_save = rb_thread_critical;
    VALUE args[3], table, objid;

    objid = rb_obj_id(obj);     /* make obj into id */
    RBASIC(obj)->klass = 0;
    rb_thread_critical = Qtrue;
    if (BUILTIN_TYPE(obj) == T_DEFERRED && RDATA(obj)->dfree) {
        (*RDATA(obj)->dfree)(DATA_PTR(obj));
    }
    args[1] = 0;
    args[2] = (VALUE)ruby_safe_level;
    for (i=0; i<RARRAY(finalizers)->len; i++) {
        args[0] = RARRAY(finalizers)->ptr[i];
        if (!args[1]) args[1] = rb_ary_new3(1, objid);
        rb_protect((VALUE(*)_((VALUE)))run_single_final, (VALUE)args, &status);
    }
    if (finalizer_table && st_delete(finalizer_table, (st_data_t*)&obj, &table)) {
        for (i=0; i<RARRAY(table)->len; i++) {
            VALUE final = RARRAY(table)->ptr[i];
            args[0] = RARRAY(final)->ptr[1];
            if (!args[1]) args[1] = rb_ary_new3(1, objid);
            args[2] = FIX2INT(RARRAY(final)->ptr[0]);
            rb_protect((VALUE(*)_((VALUE)))run_single_final, (VALUE)args, &status);
        }
    }
    rb_thread_critical = critical_save;
}

void
rb_gc_finalize_deferred()
{
    RVALUE *p = deferred_final_list;

    deferred_final_list = 0;
    if (p) {
        finalize_list(p);
        free_unused_heaps();
    }
}

void
rb_gc_call_finalizer_at_exit()
{
    RVALUE *p, *pend;
    struct heaps_slot *heap;
    int i, finalized_slots = 0;

    /* run finalizers */
    if (need_call_final && finalizer_table) {
        GC_DEBUG_PRINT("*** Calling finalizers ***\n")
        p = deferred_final_list;
        deferred_final_list = 0;
        finalize_list(p);
        for (i = 0; i < heaps_used; i++) {
            heap = &heaps[i];
            p = heaps->slot; pend = p + heaps->limit;
            while (p < pend) {
                if (FL_TEST(p, FL_FINALIZE)) {
                    if (GC_DEBUG_ON) finalized_slots++;
                    FL_UNSET(p, FL_FINALIZE);
                    run_final((VALUE)p);
                }
                p++;
            }
        }
        if (finalizer_table) {
            st_free_table(finalizer_table);
            finalizer_table = 0;
        }
    }
    /* run data object's finalizers */
    for (i = 0; i < heaps_used; i++) {
        heap = &heaps[i];
        p = heap->slot; pend = p + heap->limit;
        while (p < pend) {
            if (BUILTIN_TYPE(p) == T_DATA &&
                DATA_PTR(p) && RANY(p)->as.data.dfree &&
                RANY(p)->as.basic.klass != rb_cThread) {
                p->as.free.flags = 0;
                if ((long)RANY(p)->as.data.dfree == -1) {
                    RUBY_CRITICAL(free(DATA_PTR(p)));
                } else if (RANY(p)->as.data.dfree) {
                    if (GC_DEBUG_ON) finalized_slots++;
                    (*RANY(p)->as.data.dfree)(DATA_PTR(p));
                }
            } else if (BUILTIN_TYPE(p) == T_FILE) {
                p->as.free.flags = 0;
                if (GC_DEBUG_ON) finalized_slots++;
                rb_io_fptr_finalize(RANY(p)->as.file.fptr);
            }
            p++;
        }
    }
    GC_DEBUG_PRINTF("  Finalized %d objects\n", finalized_slots)
}

/*
 *  call-seq:
 *     ObjectSpace._id2ref(object_id) -> an_object
 *
 *  Converts an object id to a reference to the object. May not be
 *  called on an object id passed as a parameter to a finalizer.
 *
 *     s = "I am a string"                    #=> "I am a string"
 *     r = ObjectSpace._id2ref(s.object_id)   #=> "I am a string"
 *     r == s                                 #=> true
 *
 */

static VALUE
id2ref(obj, objid)
    VALUE obj, objid;
{
    unsigned long ptr, p0;
    int type;

    rb_secure(4);
    p0 = ptr = NUM2ULONG(objid);
    if (ptr == Qtrue) return Qtrue;
    if (ptr == Qfalse) return Qfalse;
    if (ptr == Qnil) return Qnil;
    if (FIXNUM_P(ptr)) return (VALUE)ptr;
    ptr = objid ^ FIXNUM_FLAG;  /* unset FIXNUM_FLAG */

    if ((ptr % sizeof(RVALUE)) == (4 << 2)) {
        ID symid = ptr / sizeof(RVALUE);
        if (rb_id2name(symid) == 0)
            rb_raise(rb_eRangeError, "%p is not symbol id value", p0);
        return ID2SYM(symid);
    }

    if (!is_pointer_to_heap((void *)ptr)||
        (type = BUILTIN_TYPE(ptr)) > T_SYMBOL || type == T_ICLASS) {
        rb_raise(rb_eRangeError, "0x%lx is not id value", p0);
    }
    if (BUILTIN_TYPE(ptr) == 0 || RBASIC(ptr)->klass == 0) {
        rb_raise(rb_eRangeError, "0x%lx is recycled object", p0);
    }
    return (VALUE)ptr;
}

/*
 *  Document-method: __id__
 *  Document-method: object_id
 *
 *  call-seq:
 *     obj.__id__       => fixnum
 *     obj.object_id    => fixnum
 *
 *  Returns an integer identifier for <i>obj</i>. The same number will
 *  be returned on all calls to <code>id</code> for a given object, and
 *  no two active objects will share an id.
 *  <code>Object#object_id</code> is a different concept from the
 *  <code>:name</code> notation, which returns the symbol id of
 *  <code>name</code>. Replaces the deprecated <code>Object#id</code>.
 */

/*
 *  call-seq:
 *     obj.hash    => fixnum
 *
 *  Generates a <code>Fixnum</code> hash value for this object. This
 *  function must have the property that <code>a.eql?(b)</code> implies
 *  <code>a.hash == b.hash</code>. The hash value is used by class
 *  <code>Hash</code>. Any hash value that exceeds the capacity of a
 *  <code>Fixnum</code> will be truncated before being used.
 */

VALUE
rb_obj_id(VALUE obj)
{
    /*
     *                32-bit VALUE space
     *          MSB ------------------------ LSB
     *  false   00000000000000000000000000000000
     *  true    00000000000000000000000000000010
     *  nil     00000000000000000000000000000100
     *  undef   00000000000000000000000000000110
     *  symbol  ssssssssssssssssssssssss00001110
     *  object  oooooooooooooooooooooooooooooo00        = 0 (mod sizeof(RVALUE))
     *  fixnum  fffffffffffffffffffffffffffffff1
     *
     *                    object_id space
     *                                       LSB
     *  false   00000000000000000000000000000000
     *  true    00000000000000000000000000000010
     *  nil     00000000000000000000000000000100
     *  undef   00000000000000000000000000000110
     *  symbol   000SSSSSSSSSSSSSSSSSSSSSSSSSSS0        S...S % A = 4 (S...S = s...s * A + 4)
     *  object   oooooooooooooooooooooooooooooo0        o...o % A = 0
     *  fixnum  fffffffffffffffffffffffffffffff1        bignum if required
     *
     *  where A = sizeof(RVALUE)/4
     *
     *  sizeof(RVALUE) is
     *  20 if 32-bit, double is 4-byte aligned
     *  24 if 32-bit, double is 8-byte aligned
     *  40 if 64-bit
     */
    if (TYPE(obj) == T_SYMBOL) {
        return (SYM2ID(obj) * sizeof(RVALUE) + (4 << 2)) | FIXNUM_FLAG;
    }
    if (SPECIAL_CONST_P(obj)) {
        return LONG2NUM((long)obj);
    }
    return (VALUE)((long)obj|FIXNUM_FLAG);
}

/* call-seq:
 *  ObjectSpace.allocated_objects => number
 *
 * Returns the count of objects allocated since the Ruby interpreter has
 * started.  This number can only increase. To know how many objects are
 * currently allocated, use ObjectSpace::live_objects
 */
static
VALUE rb_allocated_objects(VALUE self)
{
#if defined(HAVE_LONG_LONG)
    return ULL2NUM(allocated_objects);
#else
    return ULONG2NUM(allocated_objects);
#endif
}

/*
 *  The <code>GC</code> module provides an interface to Ruby's mark and
 *  sweep garbage collection mechanism. Some of the underlying methods
 *  are also available via the <code>ObjectSpace</code> module.
 */

void
Init_GC()
{
    VALUE rb_mObSpace;

    rb_mGC = rb_define_module("GC");
    rb_define_singleton_method(rb_mGC, "start", rb_gc_start, 0);
    rb_define_singleton_method(rb_mGC, "enable", rb_gc_enable, 0);
    rb_define_singleton_method(rb_mGC, "disable", rb_gc_disable, 0);
    rb_define_method(rb_mGC, "garbage_collect", rb_gc_start, 0);

    rb_mObSpace = rb_define_module("ObjectSpace");
    rb_define_module_function(rb_mObSpace, "each_object", os_each_obj, -1);
    rb_define_module_function(rb_mObSpace, "garbage_collect", rb_gc_start, 0);
    rb_define_module_function(rb_mObSpace, "add_finalizer", add_final, 1);
    rb_define_module_function(rb_mObSpace, "remove_finalizer", rm_final, 1);
    rb_define_module_function(rb_mObSpace, "finalizers", finals, 0);
    rb_define_module_function(rb_mObSpace, "call_finalizer", call_final, 1);
    rb_define_module_function(rb_mObSpace, "allocated_objects", rb_allocated_objects, 0);

    rb_define_module_function(rb_mObSpace, "define_finalizer", define_final, -1);
    rb_define_module_function(rb_mObSpace, "undefine_finalizer", undefine_final, 1);

    rb_define_module_function(rb_mObSpace, "_id2ref", id2ref, 1);

#ifdef GC_DEBUG
    rb_define_singleton_method(rb_mGC, "exorcise", gc_exorcise, 0);
    rb_define_singleton_method(rb_mGC, "stress", gc_debug_stress_get, 0);
    rb_define_singleton_method(rb_mGC, "stress=", gc_debug_stress_set, 1);
    rb_define_singleton_method(rb_mGC, "log", rb_gc_log, 1);
#endif

    rb_gc_register_address(&rb_mObSpace);
    rb_global_variable(&finalizers);
    rb_gc_unregister_address(&rb_mObSpace);
    finalizers = rb_ary_new();

    rb_global_variable(&nomem_error);
    nomem_error = rb_exc_new3(rb_eNoMemError,
                              rb_obj_freeze(rb_str_new2("failed to allocate memory")));
    OBJ_TAINT(nomem_error);
    OBJ_FREEZE(nomem_error);

    rb_define_method(rb_mKernel, "hash", rb_obj_id, 0);
    rb_define_method(rb_mKernel, "__id__", rb_obj_id, 0);
    rb_define_method(rb_mKernel, "object_id", rb_obj_id, 0);
}
