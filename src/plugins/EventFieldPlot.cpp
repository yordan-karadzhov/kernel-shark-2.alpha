// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2018 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    EventFieldPlot.cpp
 *  @brief   
 */

// C++
#include <iostream>
#include <vector>

// KernelShark
#include "plugins/event_field_plot.h"
#include "KsPlotTools.hpp"
#include "KsPlugins.hpp"

using namespace KsPlot;

/**
 * @brief Plugin's draw function.
 *
 * @param argv_c: A C pointer to be converted to KsCppArgV (C++ struct).
 * @param sd: Data stream identifier.
 * @param pid: Process Id.
 * @param draw_action: Draw action identifier.
 */
void draw_event_field(kshark_cpp_argv *argv_c,
		      int sd, int val, int draw_action)
{
	KsCppArgV *argvCpp = KS_ARGV_TO_CPP(argv_c);
	Graph *graph = argvCpp->_graph;
	plugin_efp_context *plugin_ctx;
	IsApplicableFunc checkEntry;
	int binSize(0), s0, s1;
	int64_t norm;

	if (!(draw_action & KsPlot::KSHARK_CPU_DRAW) &&
	    !(draw_action & KsPlot::KSHARK_TASK_DRAW))
		return;

	plugin_ctx = get_efp_context(sd);
	if (!plugin_ctx)
		return;

	/* Get the size of the graph's bins. */
	for (int i = 0; i < graph->size(); ++i)
		if (graph->getBin(i).mod()) {
			binSize = graph->getBin(i)._size;
			break;
		}

	s0 = graph->height() / 3;
	s1 = graph->height() / 5;

	norm = plugin_ctx->field_max - plugin_ctx->field_min;
	/* Avoid division by zero, */
	if (norm == 0)
		++norm;

	auto lamMakeShape = [=] (std::vector<const Graph *> graph,
				 std::vector<int> bin,
				 std::vector<int64_t> data,
				 Color, float) {
		int x, y, mod(binSize);
		Color c;

		x = graph[0]->getBin(bin[0])._val.x();
		y = graph[0]->getBin(bin[0])._val.y() - s0;

		if (plugin_ctx->show_max)
			mod += s1 * (data[0] - plugin_ctx->field_min) / norm;
		else
			mod += s1 * (plugin_ctx->field_max - data[0]) / norm;

		Point p0(x, y + mod), p1(x, y - mod);
		Line *l = new Line(p0, p1);
		c.setRainbowColor(mod - 1);
		l->_size = binSize * 2;
		l->_color = c;

		return l;
	};

	if (draw_action & KSHARK_CPU_DRAW)
		checkEntry = [=] (kshark_data_container *d, ssize_t i) {
			return d->data[i]->entry->cpu == val;
		};

	if (draw_action & KSHARK_TASK_DRAW)
		checkEntry = [=] (kshark_data_container *d, ssize_t i) {
			return d->data[i]->entry->pid == val;
		};

	if (plugin_ctx->show_max)
		eventFieldPlotMax(argvCpp,
				  plugin_ctx->data, checkEntry,
				  lamMakeShape,
				  {}, // Undefined color
				  0); // Undefined size
	else
		eventFieldPlotMin(argvCpp,
				  plugin_ctx->data, checkEntry,
				  lamMakeShape,
				  {}, // Undefined color
				  0); // Undefined size
}
