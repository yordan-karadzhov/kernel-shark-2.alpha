// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2009, Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2018 VMware Inc, Steven Rostedt <rostedt@goodmis.org>
 *
 */

/**
 *  @file    libkshark-hash.c
 *  @brief   Hash table of integer Id numbers.
 */

// C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

// KernelShark
#include "libkshark.h"

/**
 * @brief: quick_hash - A quick (non secured) hash alogirthm
 * @param val: The value to perform the hash on
 * @param bits: The size in bits you need to return
 *
 * This is a quick hashing function adapted from Donald E. Knuth's 32
 * bit multiplicative hash. See The Art of Computer Programming (TAOCP).
 * Multiplication by the Prime number, closest to the golden ratio of
 * 2^32.
 *
 * "bits" is used to max the result for use cases that require
 * a power of 2 return value that is less than 32 bits. Any value
 * of "bits" greater than 31 (or zero), will simply return the full hash
 * on "val".
 */
static inline uint32_t quick_hash(uint32_t val, unsigned int bits)
{
	val *= UINT32_C(2654435761);

	if (!bits || bits > 31)
		return val;

	return val & ((1 << bits) - 1);
}

static size_t hash_size(struct kshark_hash_id *hash)
{
	return (1 << hash->n_bits);
}

/**
 * Create new hash table of Ids.
 */
struct kshark_hash_id *kshark_hash_id_alloc(size_t n_bits)
{
	struct kshark_hash_id *hash;
	size_t size;

	hash = calloc(1, sizeof(*hash));
	assert(hash);

	hash->n_bits = n_bits;
	hash->count = 0;

	size = hash_size(hash);
	hash->hash = calloc(size, sizeof(*hash->hash));

	return hash;
}

/** Free the hash table of Ids. */
void kshark_hash_id_free(struct kshark_hash_id *hash)
{
	if (!hash)
		return;

	kshark_hash_id_clear(hash);
	free(hash->hash);
	free(hash);
}

/**
 * @brief Check if an Id with a given value exists in this hash table.
 */
bool kshark_hash_id_find(struct kshark_hash_id *hash, int id)
{
	uint32_t key = quick_hash(id, hash->n_bits);
	struct kshark_hash_id_item *item;

	for (item = hash->hash[key]; item; item = item->next)
		if (item->id == id)
			break;

	return !!(unsigned long)item;
}

/**
 * @brief Add Id to the hash table.
 *
 * @param hash:
 * @param id: The Id number tp be added.
 */
void kshark_hash_id_add(struct kshark_hash_id *hash, int id)
{
	uint32_t key = quick_hash(id, hash->n_bits);
	struct kshark_hash_id_item *item;

	if (kshark_hash_id_find(hash, id))
		return;

	item = calloc(1, sizeof(*item));
	assert(item);

	item->id = id;
	item->next = hash->hash[key];
	hash->hash[key] = item;
	hash->count++;
}

/**
 * @brief Remove Id from the hash table.
 */
void kshark_hash_id_remove(struct kshark_hash_id *hash, int id)
{
	struct kshark_hash_id_item *item, **next;
	int key = quick_hash(id, hash->n_bits);

	next = &hash->hash[key];
	while (*next) {
		if ((*next)->id == id)
			break;
		next = &(*next)->next;
	}

	if (!*next)
		return;

	assert(hash->count);

	hash->count--;
	item = *next;
	*next = item->next;

	free(item);
}

/** Remove (free) all Ids (items) from this hash table. */
void kshark_hash_id_clear(struct kshark_hash_id *hash)
{
	struct kshark_hash_id_item *item, *next;
	size_t size = hash_size(hash);
	int i;

	for (i = 0; i < size; i++) {
		next = hash->hash[i];
		if (!next)
			continue;

		hash->hash[i] = NULL;
		while (next) {
			item = next;
			next = item->next;
			free(item);
		}
	}

	hash->count = 0;
}

static int compare_ids(const void* a, const void* b)
{
	int arg1 = *(const int*)a;
	int arg2 = *(const int*)b;

	if (arg1 < arg2)
		return -1;

	if (arg1 > arg2)
		return 1;

	return 0;
}

/**
 * @brief Get a sorted array containing all Ids of this hash table.
 */
int *kshark_hash_ids(struct kshark_hash_id *hash)
{
	struct kshark_hash_id_item *item;
	size_t size = hash_size(hash);
	int count = 0, i;
	int *ids;

	if (!hash->count)
		return NULL;

	ids = calloc(hash->count, sizeof(*ids));
	assert(ids);

	for (i = 0; i < size; i++) {
		item = hash->hash[i];
		while (item) {
			ids[count++] = item->id;
			item = item->next;
		}
	}

	qsort(ids, hash->count, sizeof(*ids), compare_ids);

	return ids;
}
