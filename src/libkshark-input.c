// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    libkshark-input.c
 *  @brief   API for implementing new data inputs for KernelShark.
 */

// C
#ifndef _GNU_SOURCE
/** Use GNU C Library. */
#define _GNU_SOURCE

#endif

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>

// KernelShark
#include "libkshark.h"
#include "libkshark-input.h"

struct kshark_input_list *
kshark_register_input(struct kshark_context *kshark_ctx, const char *file)
{
	struct kshark_input_list *input = kshark_ctx->inputs;
	struct stat st;
	int ret;

	while (input) {
		if (strcmp(input->file, file) == 0)
			return NULL;

		input = input->next;
	}

	ret = stat(file, &st);
	if (ret < 0) {
		fprintf(stderr, "input %s not found\n", file);
		return NULL;
	}

	input = calloc(sizeof(struct kshark_input_list), 1);
	if (!input) {
		fprintf(stderr, "failed to allocate memory for input\n");
		return NULL;
	}

	input->format = KS_INVALIDE_DATA;

	if (asprintf(&input->file, "%s", file) <= 0) {
		fprintf(stderr,
			"failed to allocate memory for input file name");
		return NULL;
	}

	input->handle = dlopen(input->file, RTLD_NOW | RTLD_GLOBAL);
	if (!input->handle)
		goto fail;

	input->init = dlsym(input->handle,
			    KSHARK_INPUT_INITIALIZER_NAME);

	input->close = dlsym(input->handle,
			     KSHARK_INPUT_DEINITIALIZER_NAME);

	input->check_data = dlsym(input->handle,
				  KSHARK_INPUT_CHECK_NAME);

	if (!input->init || !input->close || !input->check_data)
		goto fail;

	input->next = kshark_ctx->inputs;
	kshark_ctx->inputs = input;

	return input;

 fail:
	fprintf(stderr, "cannot load input '%s'\n%s\n",
		input->file, dlerror());

	if (input->handle) {
		dlclose(input->handle);
		input->handle = NULL;
	}

	free(input);

	return NULL;
}

/** Close and free this input. */
static void free_input(struct kshark_input_list *input)
{
	dlclose(input->handle);
	free(input->file);
	free(input);
}

/**
 * @brief Unrgister a input.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param file: The input object file to unregister.
 */
void kshark_unregister_input(struct kshark_context *kshark_ctx,
			      const char *file)
{
	struct kshark_input_list **last;

	for (last = &kshark_ctx->inputs; *last; last = &(*last)->next) {
		if (strcmp((*last)->file, file) == 0) {
			struct kshark_input_list *this_input;
			this_input = *last;
			*last = this_input->next;

			free_input(this_input);

			return;
		}
	}
}

/**
 * @brief Free all inputs in a given list.
 *
 * @param inputs: Input location for the inputs list.
 */
void kshark_free_input_list(struct kshark_input_list *inputs)
{
	struct kshark_input_list *last;

	while (inputs) {
		last = inputs;
		inputs = inputs->next;

		free_input(last);
	}
}
