#ifndef _MARK_TABLE_H_
#define _MARK_TABLE_H_

static void rb_mark_table_init();
static void rb_mark_table_prepare();
static void rb_mark_table_reset(lifetime_t lifetime);
static void rb_mark_table_add(RVALUE *object);
static void rb_mark_table_heap_add(struct heaps_slot *hs, RVALUE *object);
static int  rb_mark_table_contains(RVALUE *object);
static int  rb_mark_table_heap_contains(struct heaps_slot *hs, RVALUE *object);
static void rb_mark_table_remove(RVALUE *object);
static void rb_mark_table_heap_remove(struct heaps_slot *hs, RVALUE *object);
static void rb_mark_table_add_filename(char *filename);
static int  rb_mark_table_contains_filename(const char *filename);
static void rb_mark_table_remove_filename(char *filename);

#ifdef GC_DEBUG
static void rb_mark_table_add_source_pos(source_position_t *source_pos);
static int  rb_mark_table_contains_source_pos(const source_position_t *source_pos);
static void rb_mark_table_remove_source_pos(source_position_t *source_pos);
#endif

#endif /* _MARK_TABLE_H_ */
