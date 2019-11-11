/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    libkshark-input.h
 *  @brief   API for implementing new data inputs for KernelShark.
 */

#ifndef _KSHARK_INPUT_H
#define _KSHARK_INPUT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Quiet warnings over documenting simple structures */
//! @cond Doxygen_Suppress

#define KSHARK_INPUT_INITIALIZER kshark_input_initializer

#define KSHARK_INPUT_DEINITIALIZER kshark_input_deinitializer

#define KSHARK_INPUT_CHECK kshark_input_check

#define _MAKE_STR(x) #x

#define MAKE_STR(x) _MAKE_STR(x)

#define KSHARK_INPUT_INITIALIZER_NAME MAKE_STR(KSHARK_INPUT_INITIALIZER)

#define KSHARK_INPUT_DEINITIALIZER_NAME MAKE_STR(KSHARK_INPUT_DEINITIALIZER)

#define KSHARK_INPUT_CHECK_NAME MAKE_STR(KSHARK_INPUT_CHECK)

struct kshark_data_stream;

struct kshark_context;

//! @endcond

typedef int (*kshark_check_data_func) (const char *filename);

typedef int (*kshark_input_load_func) (struct kshark_data_stream *);

/** Linked list of pluggable user data inputs */
struct kshark_input_list {
	/** Pointer to the next data input. */
	struct kshark_input_list	*next;

	/** The input object file to load. */
	char				*file;

	int				format;

	/** Input's object file handler. */
	void				*handle;

	/** Callback function for initialization of the data input. */
	kshark_input_load_func		init;

	/** Callback function for deinitialization of the data input. */
	kshark_input_load_func		close;

	/**
	 * Callback function for checking if the data input is applicable for
	 * a given data file.
	 */
	kshark_check_data_func		check_data;
};

struct kshark_input_list *
kshark_register_input(struct kshark_context *kshark_ctx, const char *file);

void kshark_unregister_input(struct kshark_context *kshark_ctx,
			     const char *file);

void kshark_free_input_list(struct kshark_input_list *inputs);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _KSHARK_INPUT_H
