#pragma once
#include "../deobf_types.h"

// Read-only, bounded semantic recognition. Capture runs at CMAT_FINAL; print
// revalidates the native bytes, typed loop shape, source bytes and permissions.
void capture_rotating_string_facts(cfunc_t *function);
int annotate_rotating_string_facts(cfunc_t *function);
void clear_rotating_string_facts(int64_t database_id);
