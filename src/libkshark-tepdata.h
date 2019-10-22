/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    libkshark-tepdata.h
 *  @brief   API for processing of FTRACE (trace-cmd) data.
 */

#ifndef _KSHARK_TEPDATA_H
#define _KSHARK_TEPDATA_H

// KernelShark
#include "libkshark.h"

#ifdef __cplusplus
extern "C" {
#endif

int kshark_tep_init_input(struct kshark_data_stream *stream,
			  const char *file);

int kshark_tep_init_local(struct kshark_data_stream *stream);

void kshark_tep_close_interface(struct kshark_data_stream *stream);

bool kshark_tep_filter_is_set(struct kshark_data_stream *stream);

int kshark_tep_add_filter_str(struct kshark_data_stream *stream,
			      const char *filter_str);

char *kshark_tep_filter_make_string(struct kshark_data_stream *stream,
				    int event_id);

int kshark_tep_filter_remove_event(struct kshark_data_stream *stream,
				   int event_id);

void kshark_tep_filter_reset(struct kshark_data_stream *stream);

int kshark_tep_get_event_fields(struct kshark_data_stream *stream,
				int event_id,
				char ***fields);

unsigned long long kshark_tep_read_event_field(const struct kshark_entry *entry,
					       const char *field,
					       unsigned long long err_val);

char **kshark_tracecmd_local_plugins();

struct tep_handle;

/** Get the Page event object used to parse the page. */
struct tep_handle *kshark_get_tep(struct kshark_data_stream *stream);

struct tracecmd_input;

struct tracecmd_input *kshark_get_tep_input(struct kshark_data_stream *stream);

struct tep_record;

ssize_t kshark_load_tep_records(struct kshark_context *kshark_ctx, int sd,
				struct tep_record ***data_rows);

#ifdef __cplusplus
}
#endif

#endif // _KSHARK_TEPDATA_H
