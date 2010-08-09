/**********************************************************************

  node.h -

  $Author$
  $Date$
  created at: Fri May 28 15:14:02 JST 1993

  Copyright (C) 1993-2003 Yukihiro Matsumoto

**********************************************************************/

#ifndef NODE_H
#define NODE_H

#if defined(__cplusplus)
extern "C" {
#endif

enum node_type {
    NODE_METHOD,
    NODE_FBODY,
    NODE_CFUNC,
    NODE_SCOPE,
    NODE_BLOCK,
    NODE_IF,
    NODE_CASE,
    NODE_WHEN,
    NODE_OPT_N,
    NODE_WHILE,
    NODE_UNTIL,
    NODE_ITER,
    NODE_FOR,
    NODE_BREAK,
    NODE_NEXT,
    NODE_REDO,
    NODE_RETRY,
    NODE_BEGIN,
    NODE_RESCUE,
    NODE_RESBODY,
    NODE_ENSURE,
    NODE_AND,
    NODE_OR,
    NODE_NOT,
    NODE_MASGN,
    NODE_LASGN,
    NODE_DASGN,
    NODE_DASGN_CURR,
    NODE_GASGN,
    NODE_IASGN,
    NODE_CDECL,
    NODE_CVASGN,
    NODE_CVDECL,
    NODE_OP_ASGN1,
    NODE_OP_ASGN2,
    NODE_OP_ASGN_AND,
    NODE_OP_ASGN_OR,
    NODE_CALL,
    NODE_FCALL,
    NODE_VCALL,
    NODE_SUPER,
    NODE_ZSUPER,
    NODE_ARRAY,
    NODE_ZARRAY,
    NODE_HASH,
    NODE_RETURN,
    NODE_YIELD,
    NODE_LVAR,
    NODE_DVAR,
    NODE_GVAR,
    NODE_IVAR,
    NODE_CONST,
    NODE_CVAR,
    NODE_NTH_REF,
    NODE_BACK_REF,
    NODE_MATCH,
    NODE_MATCH2,
    NODE_MATCH3,
    NODE_LIT,
    NODE_STR,
    NODE_DSTR,
    NODE_XSTR,
    NODE_DXSTR,
    NODE_EVSTR,
    NODE_DREGX,
    NODE_DREGX_ONCE,
    NODE_ARGS,
    NODE_ARGSCAT,
    NODE_ARGSPUSH,
    NODE_SPLAT,
    NODE_TO_ARY,
    NODE_SVALUE,
    NODE_BLOCK_ARG,
    NODE_BLOCK_PASS,
    NODE_DEFN,
    NODE_DEFS,
    NODE_ALIAS,
    NODE_VALIAS,
    NODE_UNDEF,
    NODE_CLASS,
    NODE_MODULE,
    NODE_SCLASS,
    NODE_COLON2,
    NODE_COLON3,
    NODE_CREF,
    NODE_DOT2,
    NODE_DOT3,
    NODE_FLIP2,
    NODE_FLIP3,
    NODE_ATTRSET,
    NODE_SELF,
    NODE_NIL,
    NODE_TRUE,
    NODE_FALSE,
    NODE_DEFINED,
    NODE_NEWLINE,
    NODE_POSTEXE,
    NODE_ALLOCA,
    NODE_DMETHOD,
    NODE_BMETHOD,
    NODE_MEMO,
    NODE_IFUNC,
    NODE_DSYM,
    NODE_ATTRASGN,
    NODE_LAST
};

typedef struct RNode {
    unsigned long flags;
    char *nd_file;
    union {
	struct RNode *node;
	ID id;
	VALUE value;
	VALUE (*cfunc)(ANYARGS);
	ID *tbl;
    } u1;
    union {
	struct RNode *node;
	ID id;
	long argc;
	VALUE value;
    } u2;
    union {
	struct RNode *node;
	ID id;
	long state;
	struct global_entry *entry;
	long cnt;
	VALUE value;
    } u3;
} NODE;

extern NODE *ruby_cref;
extern NODE *ruby_top_cref;

#define RNODE(obj)  (R_CAST(RNode)(obj))

#define nd_type(n) ((int)(((RNODE(n))->flags>>FL_USHIFT)&0xff))
#define nd_set_type(n,t) \
    RNODE(n)->flags=((RNODE(n)->flags&~FL_UMASK)|(((t)<<FL_USHIFT)&FL_UMASK))

#define NODE_LSHIFT (FL_USHIFT+8)
#define NODE_LMASK  (((long)1<<(sizeof(NODE*)*CHAR_BIT-NODE_LSHIFT))-1)
#define nd_line(n) ((unsigned int)(((RNODE(n))->flags>>NODE_LSHIFT)&NODE_LMASK))
#define nd_set_line(n,l) \
    RNODE(n)->flags=((RNODE(n)->flags&~(-1<<NODE_LSHIFT))|(((l)&NODE_LMASK)<<NODE_LSHIFT))

#define nd_head  u1.node
#define nd_alen  u2.argc
#define nd_next  u3.node

#define nd_cond  u1.node
#define nd_body  u2.node
#define nd_else  u3.node

#define nd_orig  u3.value

#define nd_resq  u2.node
#define nd_ensr  u3.node

#define nd_1st   u1.node
#define nd_2nd   u2.node

#define nd_stts  u1.node

#define nd_entry u3.entry
#define nd_vid   u1.id
#define nd_cflag u2.id
#define nd_cval  u3.value

#define nd_cnt   u3.cnt
#define nd_tbl   u1.tbl

#define nd_var   u1.node
#define nd_ibdy  u2.node
#define nd_iter  u3.node

#define nd_value u2.node
#define nd_aid   u3.id

#define nd_lit   u1.value

#define nd_frml  u1.node
#define nd_rest  u2.node
#define nd_opt   u1.node

#define nd_recv  u1.node
#define nd_mid   u2.id
#define nd_args  u3.node

#define nd_noex  u1.id
#define nd_defn  u3.node

#define nd_cfnc  u1.cfunc
#define nd_argc  u2.argc

#define nd_cpath u1.node
#define nd_super u3.node

#define nd_modl  u1.id
#define nd_clss  u1.value

#define nd_beg   u1.node
#define nd_end   u2.node
#define nd_state u3.state
#define nd_rval  u2.value

#define nd_nth   u2.argc

#define nd_tag   u1.id
#define nd_tval  u2.value

#define NEW_NODE(t,a0,a1,a2) rb_node_newnode((t),(VALUE)(a0),(VALUE)(a1),(VALUE)(a2))

#define NEW_NODE_LONGLIFE(t,a0,a1,a2) rb_node_newnode_longlife((t),(VALUE)(a0),(VALUE)(a1),(VALUE)(a2))
#define REMEMBER(x) (rb_gc_write_barrier((VALUE)(x)))

#define NEW_METHOD(n,x) NEW_NODE_LONGLIFE(NODE_METHOD,x,REMEMBER(n),0)
#define NEW_FBODY(n,i,o) NEW_NODE_LONGLIFE(NODE_FBODY,REMEMBER(n),i,REMEMBER(o))
#define NEW_DEFN(i,a,d,p) NEW_NODE_LONGLIFE(NODE_DEFN,p,i,NEW_RFUNC(a,d))
#define NEW_DEFS(r,i,a,d) NEW_NODE_LONGLIFE(NODE_DEFS,REMEMBER(r),i,NEW_RFUNC(a,d))
#define NEW_CFUNC(f,c) NEW_NODE_LONGLIFE(NODE_CFUNC,f,c,0)
#define NEW_IFUNC(f,c) NEW_NODE(NODE_IFUNC,f,c,0)
#define NEW_RFUNC(b1,b2) NEW_SCOPE(block_append(b1,b2))
#define NEW_SCOPE(b) NEW_NODE_LONGLIFE(NODE_SCOPE,local_tbl(),0,REMEMBER(b))
#define NEW_BLOCK(a) NEW_NODE_LONGLIFE(NODE_BLOCK,REMEMBER(a),0,0)
#define NEW_IF(c,t,e) NEW_NODE_LONGLIFE(NODE_IF,REMEMBER(c),REMEMBER(t),REMEMBER(e))
#define NEW_UNLESS(c,t,e) NEW_IF(c,e,t)
#define NEW_CASE(h,b) NEW_NODE_LONGLIFE(NODE_CASE,REMEMBER(h),REMEMBER(b),0)
#define NEW_WHEN(c,t,e) NEW_NODE_LONGLIFE(NODE_WHEN,REMEMBER(c),REMEMBER(t),REMEMBER(e))
#define NEW_OPT_N(b) NEW_NODE(NODE_OPT_N,0,b,0)
#define NEW_WHILE(c,b,n) NEW_NODE_LONGLIFE(NODE_WHILE,REMEMBER(c),REMEMBER(b),n)
#define NEW_UNTIL(c,b,n) NEW_NODE_LONGLIFE(NODE_UNTIL,REMEMBER(c),REMEMBER(b),n)
#define NEW_FOR(v,i,b) NEW_NODE_LONGLIFE(NODE_FOR,REMEMBER(v),REMEMBER(b),REMEMBER(i))
#define NEW_ITER(v,i,b) NEW_NODE(NODE_ITER,v,b,i)
#define NEW_BREAK(s) NEW_NODE_LONGLIFE(NODE_BREAK,REMEMBER(s),0,0)
#define NEW_NEXT(s) NEW_NODE_LONGLIFE(NODE_NEXT,REMEMBER(s),0,0)
#define NEW_REDO() NEW_NODE_LONGLIFE(NODE_REDO,0,0,0)
#define NEW_RETRY() NEW_NODE_LONGLIFE(NODE_RETRY,0,0,0)
#define NEW_BEGIN(b) NEW_NODE_LONGLIFE(NODE_BEGIN,0,REMEMBER(b),0)
#define NEW_RESCUE(b,res,e) NEW_NODE_LONGLIFE(NODE_RESCUE,REMEMBER(b),REMEMBER(res),REMEMBER(e))
#define NEW_RESBODY(a,ex,n) NEW_NODE_LONGLIFE(NODE_RESBODY,REMEMBER(n),REMEMBER(ex),REMEMBER(a))
#define NEW_ENSURE(b,en) NEW_NODE_LONGLIFE(NODE_ENSURE,REMEMBER(b),0,REMEMBER(en))
#define NEW_RETURN(s) NEW_NODE_LONGLIFE(NODE_RETURN,REMEMBER(s),0,0)
#define NEW_YIELD(a,s) NEW_NODE_LONGLIFE(NODE_YIELD,REMEMBER(a),0,s)
#define NEW_LIST(a)  NEW_ARRAY(a)
#define NEW_ARRAY(a) NEW_NODE_LONGLIFE(NODE_ARRAY,REMEMBER(a),1,0)
#define NEW_ZARRAY() NEW_NODE_LONGLIFE(NODE_ZARRAY,0,0,0)
#define NEW_HASH(a)  NEW_NODE_LONGLIFE(NODE_HASH,REMEMBER(a),0,0)
#define NEW_NOT(a)   NEW_NODE_LONGLIFE(NODE_NOT,0,REMEMBER(a),0)
#define NEW_MASGN(l,r)   NEW_NODE(NODE_MASGN,l,0,r)
#define NEW_GASGN(v,val) NEW_NODE(NODE_GASGN,v,val,rb_global_entry(v))
#define NEW_LASGN(v,val) NEW_NODE(NODE_LASGN,v,val,local_cnt(v))
#define NEW_DASGN(v,val) NEW_NODE(NODE_DASGN,v,val,0)
#define NEW_DASGN_CURR(v,val) NEW_NODE(NODE_DASGN_CURR,v,val,0)
#define NEW_IASGN(v,val) NEW_NODE(NODE_IASGN,v,val,0)
#define NEW_CDECL(v,val,path) NEW_NODE(NODE_CDECL,v,val,path)
#define NEW_CVASGN(v,val) NEW_NODE(NODE_CVASGN,v,val,0)
#define NEW_CVDECL(v,val) NEW_NODE(NODE_CVDECL,v,val,0)
#define NEW_OP_ASGN1(p,id,a) NEW_NODE_LONGLIFE(NODE_OP_ASGN1,REMEMBER(p),id,REMEMBER(a))
#define NEW_OP_ASGN2(r,i,o,val) NEW_NODE(NODE_OP_ASGN2,r,val,NEW_OP_ASGN22(i,o))
#define NEW_OP_ASGN22(i,o) NEW_NODE(NODE_OP_ASGN2,i,o,rb_id_attrset(i))
#define NEW_OP_ASGN_OR(i,val) NEW_NODE_LONGLIFE(NODE_OP_ASGN_OR,REMEMBER(i),REMEMBER(val),0)
#define NEW_OP_ASGN_AND(i,val) NEW_NODE_LONGLIFE(NODE_OP_ASGN_AND,REMEMBER(i),REMEMBER(val),0)
#define NEW_GVAR(v) NEW_NODE_LONGLIFE(NODE_GVAR,v,0,rb_global_entry(v))
#define NEW_LVAR(v) NEW_NODE_LONGLIFE(NODE_LVAR,v,0,local_cnt(v))
#define NEW_DVAR(v) NEW_NODE_LONGLIFE(NODE_DVAR,v,0,0)
#define NEW_IVAR(v) NEW_NODE_LONGLIFE(NODE_IVAR,v,0,0)
#define NEW_CONST(v) NEW_NODE_LONGLIFE(NODE_CONST,v,0,0)
#define NEW_CVAR(v) NEW_NODE_LONGLIFE(NODE_CVAR,v,0,0)
#define NEW_NTH_REF(n)  NEW_NODE_LONGLIFE(NODE_NTH_REF,0,n,local_cnt('~'))
#define NEW_BACK_REF(n) NEW_NODE_LONGLIFE(NODE_BACK_REF,0,n,local_cnt('~'))
#define NEW_MATCH(c) NEW_NODE_LONGLIFE(NODE_MATCH,REMEMBER(c),0,0)
#define NEW_MATCH2(n1,n2) NEW_NODE_LONGLIFE(NODE_MATCH2,REMEMBER(n1),REMEMBER(n2),0)
#define NEW_MATCH3(r,n2) NEW_NODE_LONGLIFE(NODE_MATCH3,REMEMBER(r),REMEMBER(n2),0)
#define NEW_LIT(l) NEW_NODE(NODE_LIT,l,0,0)
#define NEW_LIT_LONGLIFE(l) NEW_NODE_LONGLIFE(NODE_LIT,REMEMBER(l),0,0)
#define NEW_STR(s) NEW_NODE(NODE_STR,s,0,0)
#define NEW_DSTR(s) NEW_NODE_LONGLIFE(NODE_DSTR,REMEMBER(s),1,0)
#define NEW_XSTR(s) NEW_NODE_LONGLIFE(NODE_XSTR,REMEMBER(s),0,0)
#define NEW_DXSTR(s) NEW_NODE_LONGLIFE(NODE_DXSTR,s,0,0)
#define NEW_DSYM(s,l) NEW_NODE_LONGLIFE(NODE_DSYM,REMEMBER(s),1,REMEMBER(l))
#define NEW_EVSTR(n) NEW_NODE_LONGLIFE(NODE_EVSTR,0,REMEMBER(n),0)
#define NEW_CALL(r,m,a) NEW_NODE(NODE_CALL,r,m,a)
#define NEW_FCALL(m,a) NEW_NODE(NODE_FCALL,0,m,a)
#define NEW_VCALL(m) NEW_NODE_LONGLIFE(NODE_VCALL,0,m,0)
#define NEW_SUPER(a) NEW_NODE_LONGLIFE(NODE_SUPER,0,0,REMEMBER(a))
#define NEW_ZSUPER() NEW_NODE_LONGLIFE(NODE_ZSUPER,0,0,0)
#define NEW_ARGS(f,o,r) NEW_NODE(NODE_ARGS,REMEMBER(o),REMEMBER(r),f)
#define NEW_ARGSCAT(a,b) NEW_NODE_LONGLIFE(NODE_ARGSCAT,REMEMBER(a),REMEMBER(b),0)
#define NEW_ARGSPUSH(a,b) NEW_NODE_LONGLIFE(NODE_ARGSPUSH,REMEMBER(a),REMEMBER(b),0)
#define NEW_SPLAT(a) NEW_NODE(NODE_SPLAT,REMEMBER(a),0,0)
#define NEW_TO_ARY(a) NEW_NODE_LONGLIFE(NODE_TO_ARY,REMEMBER(a),0,0)
#define NEW_SVALUE(a) NEW_NODE(NODE_SVALUE,a,0,0)
#define NEW_BLOCK_ARG(v) NEW_NODE_LONGLIFE(NODE_BLOCK_ARG,v,0,local_cnt(v))
#define NEW_BLOCK_PASS(b) NEW_NODE(NODE_BLOCK_PASS,0,b,0)
#define NEW_ALIAS(n,o) NEW_NODE_LONGLIFE(NODE_ALIAS,REMEMBER(n),REMEMBER(o),0)
#define NEW_VALIAS(n,o) NEW_NODE_LONGLIFE(NODE_VALIAS,REMEMBER(n),REMEMBER(o),0)
#define NEW_UNDEF(i) NEW_NODE_LONGLIFE(NODE_UNDEF,0,REMEMBER(i),0)
#define NEW_CLASS(n,b,s) NEW_NODE_LONGLIFE(NODE_CLASS,REMEMBER(n),REMEMBER(NEW_SCOPE(b)),REMEMBER(s))
#define NEW_SCLASS(r,b) NEW_NODE_LONGLIFE(NODE_SCLASS,REMEMBER(r),REMEMBER(NEW_SCOPE(b)),0)
#define NEW_MODULE(n,b) NEW_NODE_LONGLIFE(NODE_MODULE,REMEMBER(n),REMEMBER(NEW_SCOPE(b)),0)
#define NEW_COLON2(c,i) NEW_NODE_LONGLIFE(NODE_COLON2,REMEMBER(c),i,0)
#define NEW_COLON3(i) NEW_NODE_LONGLIFE(NODE_COLON3,0,REMEMBER(i),0)
#define NEW_CREF(c,n) NEW_NODE_LONGLIFE(NODE_CREF,REMEMBER(c),0,REMEMBER(n))
#define NEW_DOT2(b,e) NEW_NODE(NODE_DOT2,b,e,0)
#define NEW_DOT3(b,e) NEW_NODE(NODE_DOT3,b,e,0)
#define NEW_ATTRSET(a) NEW_NODE_LONGLIFE(NODE_ATTRSET,a,0,0)
#define NEW_SELF() NEW_NODE_LONGLIFE(NODE_SELF,0,0,0)
#define NEW_NIL() NEW_NODE(NODE_NIL,0,0,0)
#define NEW_TRUE() NEW_NODE(NODE_TRUE,0,0,0)
#define NEW_FALSE() NEW_NODE(NODE_FALSE,0,0,0)
#define NEW_DEFINED(e) NEW_NODE_LONGLIFE(NODE_DEFINED,REMEMBER(e),0,0)
#define NEW_NEWLINE(n) NEW_NODE(NODE_NEWLINE,0,0,n)
#define NEW_PREEXE(b) NEW_SCOPE(b)
#define NEW_POSTEXE() NEW_NODE_LONGLIFE(NODE_POSTEXE,0,0,0)
#define NEW_DMETHOD(b) NEW_NODE_LONGLIFE(NODE_DMETHOD,0,0,REMEMBER(b))
#define NEW_BMETHOD(b) NEW_NODE_LONGLIFE(NODE_BMETHOD,0,0,REMEMBER(b))
#define NEW_ATTRASGN(r,m,a) NEW_NODE_LONGLIFE(NODE_ATTRASGN,REMEMBER(r),m,REMEMBER(a))

#define NOEX_PUBLIC    0
#define NOEX_NOSUPER   1
#define NOEX_PRIVATE   2
#define NOEX_PROTECTED 4
#define NOEX_MASK      6

#define NOEX_UNDEF     NOEX_NOSUPER

NODE *rb_compile_cstr _((const char*, const char*, int, int));
NODE *rb_compile_string _((const char*, VALUE, int));
NODE *rb_compile_file _((const char*, VALUE, int));

void rb_add_method _((VALUE, ID, NODE *, int));
NODE *rb_node_newnode _((enum node_type,VALUE,VALUE,VALUE));
NODE *rb_node_newnode_longlife _((enum node_type,VALUE,VALUE,VALUE));

NODE* rb_method_node _((VALUE klass, ID id));

struct global_entry *rb_global_entry _((ID));
VALUE rb_gvar_get _((struct global_entry *));
VALUE rb_gvar_set _((struct global_entry *, VALUE));
VALUE rb_gvar_defined _((struct global_entry *));

typedef unsigned int rb_event_t;

#define RUBY_EVENT_NONE     0x00
#define RUBY_EVENT_LINE     0x01
#define RUBY_EVENT_CLASS    0x02
#define RUBY_EVENT_END      0x04
#define RUBY_EVENT_CALL     0x08
#define RUBY_EVENT_RETURN   0x10
#define RUBY_EVENT_C_CALL   0x20
#define RUBY_EVENT_C_RETURN 0x40
#define RUBY_EVENT_RAISE    0x80
#define RUBY_EVENT_ALL      0xff

typedef void (*rb_event_hook_func_t) _((rb_event_t,NODE*,VALUE,ID,VALUE));
NODE *rb_copy_node_scope _((NODE *, NODE *));
void rb_add_event_hook _((rb_event_hook_func_t,rb_event_t));
int rb_remove_event_hook _((rb_event_hook_func_t));

#if defined(HAVE_GETCONTEXT) && defined(HAVE_SETCONTEXT)
#include <ucontext.h>
#define USE_CONTEXT
#endif
#include <setjmp.h>
#include "st.h"

#ifdef USE_CONTEXT
typedef struct {
    ucontext_t context;
    volatile int status;
} rb_jmpbuf_t[1];
#else
typedef RUBY_JMP_BUF rb_jmpbuf_t;
#endif

enum rb_thread_status {
    THREAD_TO_KILL,
    THREAD_RUNNABLE,
    THREAD_STOPPED,
    THREAD_KILLED,
};

typedef struct rb_thread *rb_thread_t;

struct rb_thread {
    rb_thread_t next, prev;
    rb_jmpbuf_t context;
#if (defined _WIN32 && !defined _WIN32_WCE) || defined __CYGWIN__
    unsigned long win32_exception_list;
#endif

    VALUE result;

    size_t stk_len;
    size_t stk_max;
    size_t stk_size;
    VALUE *stk_ptr;
    VALUE *stk_pos;
    VALUE *stk_base;
    VALUE *guard;
    VALUE *gc_stack_end;
#ifdef __ia64
    size_t bstr_len;
    size_t bstr_max;
    VALUE *bstr_ptr;
    VALUE *bstr_pos;
#endif

    struct FRAME *frame;
    struct SCOPE *scope;
    struct RVarmap *dyna_vars;
    struct BLOCK *block;
    struct iter *iter;
    struct tag *tag;
    VALUE klass;
    VALUE wrapper;
    NODE *cref;

    int flags;		/* misc. states (vmode/rb_trap_immediate/raised) */

    NODE *node;

    int tracing;
    VALUE errinfo;
    VALUE last_status;
    VALUE last_line;
    VALUE last_match;

    int safe;

    enum rb_thread_status status;
    int wait_for;
    int fd;
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    int select_value;
    double delay;
    rb_thread_t join;

    int abort;
    int priority;
    VALUE thgroup;

    struct st_table *locals;

    VALUE thread;

    VALUE sandbox;
};

extern VALUE (*ruby_sandbox_save)_((rb_thread_t));
extern VALUE (*ruby_sandbox_restore)_((rb_thread_t));
extern rb_thread_t rb_curr_thread;
extern rb_thread_t rb_main_thread;

enum {
    RAISED_EXCEPTION     = 0x1000,
    RAISED_STACKOVERFLOW = 0x2000,
    RAISED_NOMEMORY      = 0x4000,
    RAISED_MASK          = 0xf000
};
int rb_thread_set_raised(rb_thread_t th);
int rb_thread_reset_raised(rb_thread_t th);
#define rb_thread_raised_set(th, f)   ((th)->flags |= (f))
#define rb_thread_raised_reset(th, f) ((th)->flags &= ~(f))
#define rb_thread_raised_p(th, f)     (((th)->flags & (f)) != 0)
#define rb_thread_raised_clear(th)    (rb_thread_raised_reset(th, RAISED_MASK))

#if defined(__cplusplus)
}  /* extern "C" { */
#endif

#endif
