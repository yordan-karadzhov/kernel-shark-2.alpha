// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    hello_kernel.c
 *  @brief   Example plugin.
 */

// C
#include <stdio.h>

// KernelShark
#include "libkshark.h"
#include "libkshark-plot.h"
#include "libkshark-plugin.h"

char *font_file = NULL;
struct ksplot_font mono_oblique_16;

static void draw_hello(struct kshark_cpp_argv *argv_c, int sd,
		       int val, int draw_action)
{
	if (!ksplot_font_is_loaded(&mono_oblique_16))
		ksplot_init_font(&mono_oblique_16, 16, font_file);

	ksplot_print_text(&mono_oblique_16, NULL, 100, 30, "hello kernel!");
}

/** Load this plugin. */
int KSHARK_PLOT_PLUGIN_INITIALIZER(struct kshark_data_stream *stream)
{
	printf("--> @ hello kernel init %i\n", stream->stream_id);

	if (!font_file)
		font_file = ksplot_find_font_file("FreeMono",
						  "FreeMonoOblique");
	if (!font_file)
		return 0;

	kshark_register_draw_handler(stream, draw_hello);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLOT_PLUGIN_DEINITIALIZER(struct kshark_data_stream *stream)
{
	printf("<-- @ hello kernel close %i\n", stream->stream_id);

	kshark_unregister_draw_handler(stream, draw_hello);

	return 1;
}
