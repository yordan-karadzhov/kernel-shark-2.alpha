// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
  *  @file    KsPlugins.cpp
  *  @brief   KernelShark C++ plugin declarations.
  */

// C++
#include<iostream>

// KernelShark
#include "KsPlugins.hpp"

using namespace KsPlot;

typedef std::forward_list<std::pair<int, int64_t>> PlotPointList;

typedef std::function<void(int, kshark_data_container *, ssize_t,
			   PlotPointList *)> pushFunc;

typedef std::function<void(kshark_data_container *, ssize_t,
			   PlotPointList *)> resolveFunc;

static void pointPlot(KsCppArgV *argvCpp, IsApplicableFunc isApplicable,
		      pluginShapeFunc makeShape, Color col, float size)
{
	int nBins = argvCpp->_graph->size();

	for (int bin = 0; bin < nBins; ++bin)
		if (isApplicable(nullptr, bin))
			argvCpp->_shapes->push_front(makeShape({argvCpp->_graph},
							       {bin}, {},
							       col, size));
}

//! @cond Doxygen_Suppress

#define PLUGIN_MIN_BOX_SIZE 4

//! @endcond

static std::pair<ssize_t, ssize_t>
getRange(kshark_trace_histo *histo, kshark_data_container *data)
{
	ssize_t firstEntry, lastEntry;
	std::pair<ssize_t, ssize_t> err(-1, -2);

	firstEntry = kshark_find_entry_field_by_time(histo->min,
						     data->data,
						     0,
						     data->size - 1);

	if (firstEntry == BSEARCH_ALL_SMALLER)
		return err;

	if (firstEntry == BSEARCH_ALL_GREATER)
		firstEntry = 0;

	lastEntry = kshark_find_entry_field_by_time(histo->max,
						    data->data,
						    firstEntry,
						    data->size - 1);

	if (lastEntry == BSEARCH_ALL_GREATER)
		return err;

	if (lastEntry == BSEARCH_ALL_SMALLER)
		lastEntry = data->size - 1;

	return {firstEntry, lastEntry};
}

static PlotPointList
getInBinEvents(kshark_trace_histo *histo,
	       kshark_data_container *data,
	       IsApplicableFunc isApplicable,
	       pushFunc push,
	       resolveFunc resolve)
{
	int bin, lastBin(-1);
	PlotPointList buffer;

	auto lamIsOverflow = [] (int bin) {
		return (bin == UPPER_OVERFLOW_BIN ||
			bin == LOWER_OVERFLOW_BIN) ? true : false;
	};

	auto range = getRange(histo, data);

	for (ssize_t i = range.second; i >= range.first; --i) {
		if (isApplicable(data, i)) {
			bin = ksmodel_get_bin(histo, data->data[i]->entry);
			if (lamIsOverflow(bin))
				continue;

			if (bin != lastBin) {
				push(bin, data, i, &buffer);
				lastBin = bin;
			} else {
				resolve(data, i, &buffer);
			}
		}
	}

	return buffer;
}

static PlotPointList
getLastInBinEvents(kshark_trace_histo *histo, kshark_data_container *data,
		   IsApplicableFunc isApplicable)
{
	pushFunc push = [] (int bin, kshark_data_container *data, ssize_t i,
			    PlotPointList *list) {
		list->push_front({bin, data->data[i]->entry->ts});
	};

	/*
	 * Do not resolve. This means that only the very last (in time)
	 * appearance of the event in the bin will be visualized.
	 */
	resolveFunc resolve = [] (kshark_data_container *data, ssize_t i,
				  PlotPointList *list) {};

	return getInBinEvents(histo, data, isApplicable, push, resolve);
}

static PlotPointList
getMaxInBinEvents(kshark_trace_histo *histo, kshark_data_container *data,
		 IsApplicableFunc isApplicable)
{
	pushFunc push = [] (int bin, kshark_data_container *data, ssize_t i,
			    PlotPointList *list) {
		list->push_front({bin, data->data[i]->field});
	};

	/* Overwrite if bigger. */
	resolveFunc resolve = [] (kshark_data_container *data, ssize_t i,
				  PlotPointList *list) {
		if (list->front().second < data->data[i]->field)
			list->front().second = data->data[i]->field;
	};

	return getInBinEvents(histo, data, isApplicable, push, resolve);
}


static PlotPointList
getMinInBinEvents(kshark_trace_histo *histo, kshark_data_container *data,
		 IsApplicableFunc isApplicable)
{
	pushFunc push = [] (int bin, kshark_data_container *data, ssize_t i,
			    PlotPointList *list) {
		list->push_front({bin, data->data[i]->field});
	};

	/* Overwrite if smaller. */
	resolveFunc resolve = [] (kshark_data_container *data, ssize_t i,
				  PlotPointList *list) {
		if (list->front().second > data->data[i]->field)
			list->front().second = data->data[i]->field;
	};

	return getInBinEvents(histo, data, isApplicable, push, resolve);
}

static void intervalPlot(kshark_trace_histo *histo,
			 kshark_data_container *dataEvtA,
			 IsApplicableFunc checkFieldA,
			 kshark_data_container *dataEvtB,
			 IsApplicableFunc checkFieldB,
			 Graph *graph,
			 PlotObjList *shapes,
			 pluginShapeFunc makeShape,
			 Color col,
			 float size)
{
	PlotPointList bufferA, bufferB;
	int binA, binB;
	int64_t tsB;

	auto lamGetBin = [] (auto it) {return (*it).first;};

	auto lamGetTime = [] (auto it) {return (*it).second;};

	bufferA = getLastInBinEvents(histo,
				     dataEvtA,
				     checkFieldA);

	bufferB = getLastInBinEvents(histo,
				     dataEvtB,
				     checkFieldB);

	if (bufferA.empty() || bufferB.empty())
		return;

	auto itA = bufferA.cbegin();
	auto itB = bufferB.cbegin();
	while (itA != bufferA.cend() && itB != bufferB.cend()) {
		binA = lamGetBin(itA);

		/*
		 * We will draw a shape between "Event A" and "Event B".
		 * Because the shape starts with "Event A", we will skip all
		 * "Event B" entries before the "Event A" entry.
		 */
		do {
			tsB = lamGetTime(itB);
			binB = lamGetBin(itB);
			itB++;
		} while (itB != bufferB.cend() && tsB < lamGetTime(itA));

		/*
		 * The shape ends with "Event B" and we already have this
		 * event. However, we have to make sure that we will start the
		 * shape from the very last "Event A" entry, which is rigth
		 * before the "Event B" entry, which we already selected.
		 */
		while (itA != bufferA.cend() && lamGetTime(itA) < tsB) {
			binA = lamGetBin(itA);
			itA++;
		}

		if (binB - binA >= PLUGIN_MIN_BOX_SIZE)
			shapes->push_front(makeShape({graph}, {binA, binB}, {},
						     col, size));
	}
}

void eventPlot(KsCppArgV *argvCpp, IsApplicableFunc isApplicable,
	       pluginShapeFunc makeShape, Color col, float size)
{
	try {
		pointPlot(argvCpp, isApplicable, makeShape, col, size);
	} catch (const std::exception &exc) {
		std::cerr << "Exception in eventPlot\n"
			  << exc.what() << std::endl;
	}
}

enum class PlotSymptom {
	Maximum,
	Minimum,
};

void eventFieldPlot(KsCppArgV *argvCpp,
		    kshark_data_container *dataEvt,
		    IsApplicableFunc checkField,
		    PlotSymptom s,
		    pluginShapeFunc makeShape,
		    KsPlot::Color col,
		    float size)
{
	PlotPointList buffer;

	if (dataEvt->size == 0)
		return;

	if (!dataEvt->sorted)
		kshark_data_container_sort(dataEvt);

	try {
		if (s == PlotSymptom::Maximum)
			buffer = getMaxInBinEvents(argvCpp->_histo,
						   dataEvt, checkField);

		if  (s == PlotSymptom::Minimum)
			buffer = getMinInBinEvents(argvCpp->_histo,
						   dataEvt, checkField);

		for (auto const &i: buffer) {
			argvCpp->_shapes->push_front(makeShape({argvCpp->_graph},
							       {i.first},
							       {i.second},
							       col, size));
		}
	} catch (const std::exception &exc) {
		std::cerr << "Exception in eventFieldPlot\n"
			  << exc.what() << std::endl;
	}
}

void eventFieldPlotMax(KsCppArgV *argvCpp,
		       kshark_data_container *dataEvt,
		       IsApplicableFunc checkField,
		       pluginShapeFunc makeShape,
		       KsPlot::Color col,
		       float size)
{
	eventFieldPlot(argvCpp, dataEvt, checkField,
		       PlotSymptom::Maximum,
		       makeShape, col, size);
}

void eventFieldPlotMin(KsCppArgV *argvCpp,
		       kshark_data_container *dataEvt,
		       IsApplicableFunc checkField,
		       pluginShapeFunc makeShape,
		       KsPlot::Color col,
		       float size)
{
	eventFieldPlot(argvCpp, dataEvt, checkField,
		       PlotSymptom::Minimum,
		       makeShape, col, size);
}

void eventFieldIntervalPlot(KsCppArgV *argvCpp,
			    kshark_data_container *dataEvtA,
			    IsApplicableFunc checkFieldA,
			    kshark_data_container *dataEvtB,
			    IsApplicableFunc checkFieldB,
			    pluginShapeFunc makeShape,
			    KsPlot::Color col,
			    float size)
{
	if (dataEvtA->size == 0 || dataEvtB->size == 0)
		return;

	if (!dataEvtA->sorted)
		kshark_data_container_sort(dataEvtA);

	if (!dataEvtB->sorted)
		kshark_data_container_sort(dataEvtB);

	try {
		intervalPlot(argvCpp->_histo,
			     dataEvtA, checkFieldA,
			     dataEvtB, checkFieldB,
			     argvCpp->_graph,
			     argvCpp->_shapes,
			     makeShape, col, size);
	} catch (const std::exception &exc) {
		std::cerr << "Exception in eventFieldIntervalPlot\n"
			  << exc.what() << std::endl;
	}
}
