// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2020 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    LatencyPlot.cpp
 *  @brief
 */

// C++
#include <unordered_map>
#include <iostream>

// KernelShark
#include "plugins/latency_plot.h"
#include "KsPlotTools.hpp"
#include "KsPlugins.hpp"

/** A pair of events defining the latency. */
typedef std::pair<kshark_entry *, kshark_entry *> LatencyPair;

/** Hash table of latency pairs. */
typedef std::unordered_multimap<int, LatencyPair> LatencyHashTable;

LatencyHashTable latencyCPUMap, latencyTaskMap;

/**
 * Macro used to forward the arguments and construct the pair directly into
 * a hash table without unnecessary copies (or moves).
 */
#define LATENCY_EMPLACE(map, key ,eA, eB) \
	map.emplace(std::piecewise_construct, \
		    std::forward_as_tuple(key), \
		    std::forward_as_tuple(eA, eB)); \

using namespace KsPlot;

/*
 * A second pass over the data is used to populate the hash tables of latency
 * pairs.
 */
static void secondPass(plugin_latency_context *plugin_ctx)
{
	kshark_data_field_int64	**dataA = plugin_ctx->data[0]->data;
	kshark_data_field_int64	**dataB = plugin_ctx->data[1]->data;

	size_t nEvtAs = plugin_ctx->data[0]->size;
	size_t nEvtBs = plugin_ctx->data[1]->size;
	int64_t timeA, timeANext, valFieldA;
	size_t iB(0);

	/*
	 * The order of the events in the container is the same as in the raw
	 * data in the file. This means the data is not sorted in time.
	 */
	kshark_data_container_sort(plugin_ctx->data[0]);
	kshark_data_container_sort(plugin_ctx->data[1]);

	for (size_t iA = 0; iA < nEvtAs; ++iA) {
		timeA = dataA[iA]->entry->ts;
		valFieldA = dataA[iA]->field;

		/*
		 * Find the time of the next "A event" having the same field
		 * value.
		 */
		timeANext = INT64_MAX;
		for (size_t i = iA + 1; i <nEvtAs; ++i) {
			if (dataA[i]->field == valFieldA) {
				timeANext = dataA[i]->entry->ts;
				break;
			}
		}

		for (size_t i = iB; i < nEvtBs; ++i) {
			if (dataB[i]->entry->ts < timeA) {
				/*
				 * We only care about the "B evenys" that are
				 * after (in time) the current "A event".
				 * Skip these "B events" when you search to
				 * pair the next "A event".
				 */
				++iB;
				continue;
			}

			if (dataB[i]->entry->ts > timeANext) {
				/*
				 * We already bypassed in time the next
				 * "A event" having the same field value.
				 */
				break;
			}

			if (dataB[i]->field == valFieldA) {
				int64_t delta = dataB[i]->entry->ts - timeA;

				if (delta > plugin_ctx->max_latency)
					plugin_ctx->max_latency = delta;

				/*
				 * Store this pair of events in the hash tables.
				 *
				 * Use the CPU as a key.
				 */
				LATENCY_EMPLACE(latencyCPUMap,
						dataB[i]->entry->cpu,
						dataA[iA]->entry,
						dataB[i]->entry)

				/*
				 * Use the PID as a key.
				 */
				LATENCY_EMPLACE(latencyTaskMap,
						dataB[i]->entry->pid,
						dataA[iA]->entry,
						dataB[i]->entry)
				break;
			}
		}
	}
}

#define LIFT_BASE(point, graph) \
	point.setY(point.y() - graph->height() * .8) \

Line *plotLine(const Point &p0, const Point &p1)
{
	Line *l = new Line(p0, p1);
	l->_color = {255, 165, 0}; // Orange
	return l;
}

Line *baseLine(Graph *graph)
{
	Point p0, p1;

	p0 = graph->getBin(0)._base;
	LIFT_BASE(p0, graph);
	p1 = graph->getBin(graph->size() - 1)._base;
	LIFT_BASE(p1, graph);

	return plotLine(p0, p1);
}

Line *tick(Graph *graph, int bin, int height)
{
	Point p0, p1;

	p0 = graph->getBin(bin)._base;
	LIFT_BASE(p0, graph);
	p1 = p0;
	p1.setY(p1.y() - height);

	return plotLine(p0, p1);

}

void draw_latency(struct kshark_cpp_argv *argv_c,
			int sd, int val, int draw_action)
{
	plugin_latency_context *plugin_ctx = get_latency_context(sd);
	struct kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	kshark_trace_histo *histo;
	LatencyHashTable *hash;
	KsCppArgV *argvCpp;
	PlotObjList *shapes;
	Graph *thisGraph;
	int graphHeight;

	if (!plugin_ctx)
		return;

	if (!plugin_ctx->second_pass_done) {
		/* The second pass is not done yet. */
		secondPass(plugin_ctx);
		plugin_ctx->second_pass_done = true;
	}

	if (!kshark_instance(&kshark_ctx))
		return;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	/* Retrieve the arguments (C++ objects). */
	argvCpp = KS_ARGV_TO_CPP(argv_c);
	thisGraph = argvCpp->_graph;

	if (thisGraph->size() == 0)
		return;

	graphHeight = thisGraph->height();
	shapes = argvCpp->_shapes;
	histo = argvCpp->_histo;

	/* Start by drawing the base line of the Latency plot. */
	shapes->push_front(baseLine(thisGraph));

	auto lamScaledDelta = [=] (kshark_entry *eA, kshark_entry *eB) {
		double height;

		height = (eB->ts - eA->ts) / (double) plugin_ctx->max_latency;
		height *= graphHeight * .6;
		return height + 2;
	};

	auto lamPlotLat = [=] (auto p) {
		kshark_entry *eA = p.second.first;
		kshark_entry *eB = p.second.second;
		int binB = ksmodel_get_bin(histo, eB);

		if (binB < 0)
			return;

		shapes->push_front(tick(thisGraph, binB,
					lamScaledDelta(eA, eB)));
	};

	/*
	 * Use the latency hash tables to get all pairs that are relevant for
	 * this plot.
	 */
	if (draw_action & KSHARK_CPU_DRAW)
		hash = &latencyCPUMap;
	else if (draw_action & KSHARK_TASK_DRAW)
		hash = &latencyTaskMap;

	auto range = hash->equal_range(val);
	std::for_each(range.first, range.second, lamPlotLat);
}
