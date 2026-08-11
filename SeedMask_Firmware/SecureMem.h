/**
 * Minimal secure buffer wipe (compiler must not remove).
 * Use after crypto outputs and decrypted blobs before free().
 */
#pragma once

#include <stddef.h>

void secure_memzero(void* p, size_t n);
