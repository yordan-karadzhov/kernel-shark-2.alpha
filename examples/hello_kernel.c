// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    hello_kernel.c
 *  @brief   Example plugin.
 */

// C
#ifndef _GNU_SOURCE
/** Use GNU C Library. */
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>

// KernelShark
#include "libkshark.h"
#include "libkshark-plot.h"
#include "libkshark-plugin.h"

char *font_file = NULL;
struct ksplot_font mono_oblique_16;

static void nop_action(struct kshark_context *kshark_ctx, void *rec,
		       struct kshark_entry *entry)
{}

static void draw_hello(struct kshark_cpp_argv *argv_c, int sd,
		       int val, int draw_action)
{
	if (!ksplot_font_is_loaded(&mono_oblique_16))
		ksplot_init_font(&mono_oblique_16, 16, font_file);

	if (sd != 0)
		return;

	ksplot_print_text(&mono_oblique_16, NULL, 100, 30, "hello kernel!");
}

/** Load this plugin. */
int KSHARK_PLUGIN_INITIALIZER(struct kshark_context *kshark_ctx, int sd)
{
	printf("--> @ hello kernel init %i\n", sd);

	if (!font_file)
		font_file = ksplot_find_font_file("FreeMono",
						  "FreeMonoOblique");
	if (!font_file)
		return 0;

	kshark_register_event_handler(&kshark_ctx->event_handlers,
				      KS_PLUGIN_NO_EVENT,
				      sd,
				      nop_action,
				      draw_hello);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLUGIN_DEINITIALIZER(struct kshark_context *kshark_ctx, int sd)
{
	printf("<-- @ hello kernel close %i\n", sd);

	kshark_unregister_event_handler(&kshark_ctx->event_handlers,
					KS_PLUGIN_NO_EVENT,
					sd,
					nop_action,
					draw_hello);

	return 1;
}
