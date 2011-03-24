/**
 * A mark table, used during a mark-and-sweep garbage collection cycle.
 *
 * This implementation is somewhat slower than default MRI, but is
 * copy-on-write friendly. It stores mark information for objects in a bit
 * field located at the beginning of the heap. Mark information for filenames
 * are stored in a pointer set.
 */
#ifndef _MARK_TABLE_C_
#define _MARK_TABLE_C_

#include "pointerset.h"

/* A mark table for filenames and objects that are not on the heap. */
static PointerSet *mark_table = NULL;
static struct heaps_slot *last_heap = NULL;

static inline struct heaps_slot *
find_heap_slot_for_object(RVALUE *object)
{
	register int i;

	/* Look in the cache first. */
	if (last_heap != NULL && object >= last_heap->slot
	 && object < last_heap->slotlimit) {
		return last_heap;
	}
	for (i = 0; i < heaps_used; i++) {
		struct heaps_slot *heap = &heaps[i];
		if (object >= heap->slot
		 && object < heap->slotlimit) {
			/* Cache this result. According to empirical evidence, the chance is
			 * high that the next lookup will be for the same heap slot.
			 */
			last_heap = heap;
			return heap;
		}
	}
	return NULL;
}

static inline void
find_position_in_bitfield(struct heaps_slot *hs, RVALUE *object,
                          unsigned int *bitfield_index, unsigned int *bitfield_offset)
{
	unsigned int index;
	index = object - hs->slot;
	
	/*
	 * We use bit operators to calculate the position in the bit field, whenever possible.
	 * This only works if sizeof(int) is a multiple of 2, but I don't know of any platform
	 * on which that is not true.
	 */
	if (sizeof(int) == 4 || sizeof(int) == 8 || sizeof(int) == 16) {
		int int_bits_log; /* Must be equal to the base 2 logarithm of sizeof(int) * 8 */
		
		switch (sizeof(int)) {
		case 4:
			int_bits_log = 5;
			break;
		case 8:
			int_bits_log = 6;
			break;
		case 16:
			int_bits_log = 7;
			break;
		default:
			int_bits_log = 0; /* Shut up compiler warning. */
			abort();
		}
		*bitfield_index = index >> int_bits_log;
		*bitfield_offset = index & ((sizeof(int) * 8) - 1);
	} else {
		*bitfield_index = index / (sizeof(int) * 8);
		*bitfield_offset = index % (sizeof(int) * 8);
	}
}


static void
rb_mark_table_init()
{
	if (mark_table == NULL) {
		mark_table = pointer_set_new();
	}
}

static void
rb_mark_table_prepare()
{
	last_heap = NULL;
}

static void
rb_mark_table_reset(lifetime_t lifetime)
{
    int i;
    for (i = 0; i < heaps_used; i++) {
        if (heaps[i].lifetime == lifetime) {
            MEMZERO(heaps[i].marks, int, heaps[i].marks_size);
        }
    }
}

static inline void
rb_mark_table_add(RVALUE *object)
{
	struct heaps_slot *hs;
	unsigned int bitfield_index, bitfield_offset;

	hs = find_heap_slot_for_object(object);
	if (hs != NULL) {
		find_position_in_bitfield(hs, object, &bitfield_index, &bitfield_offset);
		hs->marks[bitfield_index] |= (1 << bitfield_offset);
	} else {
		pointer_set_insert(mark_table, (void *) object);
	}
}

static inline void
rb_mark_table_heap_add(struct heaps_slot *hs, RVALUE *object)
{
	unsigned int bitfield_index, bitfield_offset;
	find_position_in_bitfield(hs, object, &bitfield_index, &bitfield_offset);
	hs->marks[bitfield_index] |= (1 << bitfield_offset);
}

static inline int
rb_mark_table_contains(RVALUE *object)
{
	struct heaps_slot *hs;
	unsigned int bitfield_index, bitfield_offset;

	hs = find_heap_slot_for_object(object);
	if (hs != NULL) {
		find_position_in_bitfield(hs, object, &bitfield_index, &bitfield_offset);
		return hs->marks[bitfield_index] & (1 << bitfield_offset);
	} else {
		return pointer_set_contains(mark_table, (void *) object);
	}
}

static inline int
rb_mark_table_heap_contains(struct heaps_slot *hs, RVALUE *object)
{
	unsigned int bitfield_index, bitfield_offset;
	find_position_in_bitfield(hs, object, &bitfield_index, &bitfield_offset);
	last_heap = hs;
	return hs->marks[bitfield_index] & (1 << bitfield_offset);
}

static inline void
rb_mark_table_remove(RVALUE *object)
{
	struct heaps_slot *hs;
	unsigned int bitfield_index, bitfield_offset;

	hs = find_heap_slot_for_object(object);
	if (hs != NULL) {
		find_position_in_bitfield(hs, object, &bitfield_index, &bitfield_offset);
		hs->marks[bitfield_index] &= ~(1 << bitfield_offset);
	} else {
		pointer_set_delete(mark_table, (void *) object);
	}
}

static inline void
rb_mark_table_heap_remove(struct heaps_slot *hs, RVALUE *object)
{
	unsigned int bitfield_index, bitfield_offset;
	find_position_in_bitfield(hs, object, &bitfield_index, &bitfield_offset);
	hs->marks[bitfield_index] &= ~(1 << bitfield_offset);
}

static inline void
rb_mark_table_add_filename(char *filename)
{
	pointer_set_insert(mark_table, (void *) filename);
}

static inline int
rb_mark_table_contains_filename(const char *filename)
{
	return pointer_set_contains(mark_table, (void *) filename);
}

static inline void
rb_mark_table_remove_filename(char *filename)
{
	pointer_set_delete(mark_table, (void *) filename);
}

#ifdef GC_DEBUG
static inline void
rb_mark_table_add_source_pos(source_position_t *source_pos)
{
    pointer_set_insert(mark_table, (void *) source_pos);
}

static inline int
rb_mark_table_contains_source_pos(const source_position_t *source_pos)
{
    return pointer_set_contains(mark_table, (void *) source_pos);
}

static inline void
rb_mark_table_remove_source_pos(source_position_t *source_pos)
{
    pointer_set_delete(mark_table, (void *) source_pos);
}
#endif

#endif /* _MARK_TABLE_C_ */
