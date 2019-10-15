// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2018 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

// C
#include <getopt.h>

// C++
#include <vector>
#include <iostream>
#include <sstream>

// OpenGL
#include <GL/freeglut.h>

// KernelShark
#include "libkshark.h"
#include "KsPlotTools.hpp"

using namespace std;

#define GRAPH_HEIGHT		40   // width of the graph in pixels
#define GRAPH_H_MARGIN		15   // size of the white space surrounding
				     // the graph
#define GRAPH_LABEL_WIDTH	80   // width of the graph's label in pixels
#define WINDOW_WIDTH		800  // width of the screen window in pixels
#define WINDOW_HEIGHT		480  // height of the scrren window in pixels

#define default_file (char*)"trace.dat"

struct kshark_trace_histo	histo;
vector<KsPlot::Graph *>		graphs;
struct ksplot_font		font;
int stream_id;

void usage(const char *prog)
{
	cout << "Usage: " << prog << endl;
	cout << "  -h	Display this help message.\n";
	cout << "  -s	Draw shapes. This demonstrates how to draw simple "
	     << "geom. shapes.\n";
	cout << "  -i	<file>	Input file and draw animated graphs.\n";
	cout << "  No args.	Import " << default_file
	     << " and draw animated graphs.\n";
}

static void makeScene(int width, int height)
{
	/* Set Display mode. */
	glutInitDisplayMode(GLUT_SINGLE | GLUT_RGB);

	/* Prevent the program from exiting when a window is closed. */
	glutSetOption(GLUT_ACTION_ON_WINDOW_CLOSE,
		      GLUT_ACTION_GLUTMAINLOOP_RETURNS);

	/* Set window size. */
	glutInitWindowSize(width, height);

	/* Set window position on screen. */
	glutInitWindowPosition(50, 50);

	/* Open the screen window. */
	glutCreateWindow("KernelShark Plot");
}

/* An example function drawing something. */
void drawShapes()
{
	/* Clear the screen. */
	glClear(GL_COLOR_BUFFER_BIT);

	KsPlot::Triangle t;
	KsPlot::Point a(200, 100), b(200, 300), c(400, 100);
	t.setPoint(0, a);
	t.setPoint(1, b);
	t.setPoint(2, c);

	/* Set RGB color. */
	t._color = {100, 200, 50};
	t.draw();

	/* Print/draw "Hello Kernel!". */
	KsPlot::Color col = {50, 150, 255};
	KsPlot::TextBox tb(&font, "Hello Kernel!", col, {250, 70}, 250);
	tb.draw();

	KsPlot::Rectangle r;
	KsPlot::Point d(400, 200), e(400, 300), f(500, 300), g(500, 200);
	r.setPoint(0, d);
	r.setPoint(1, e);
	r.setPoint(2, f);
	r.setPoint(3, g);

	/* Set RGB color. */
	r._color = {150, 50, 250};
	r._size = 3;

	/* Do not fiil the rectangle. Draw the contour only. */
	r.setFill(false);
	r.draw();

	glFlush();
}

/* An example function demonstrating Zoom In and Zoom Out. */
void play()
{
	KsPlot::ColorTable taskColors = KsPlot::getTaskColorTable();
	KsPlot::ColorTable cpuColors = KsPlot::getCPUColorTable();
	vector<KsPlot::Graph *>::iterator it;
	vector<int> CPUs, Tasks;
	bool zoomIn(true);
	int base;
	size_t i;

	CPUs = {3, 4, 6};
	Tasks = {}; // Add valid pids here, if you want task plots.

	auto lamAddGraph = [&] (KsPlot::Graph *g) {
		/* Set the dimensions of the Graph. */
		g->setHeight(GRAPH_HEIGHT);

		/*
		 * Set the Y coordinate of the Graph's base.
		 * Remember that the "Y" coordinate is inverted.
		 */
		base = 1.7 * GRAPH_HEIGHT * (i + 1);
		g->setBase(base);

		g->setLabelAppearance(&font, {160, 255, 255}, GRAPH_LABEL_WIDTH,
							      GRAPH_H_MARGIN);
		std::stringstream ss;
		ss << "CPU " << CPUs[i];
		g->setLabelText(ss.str());

		/* Add the Graph. */
		graphs.push_back(g);
	};

	for (i = 0; i < CPUs.size(); ++i)
		lamAddGraph(new KsPlot::Graph(&histo, &taskColors,
						      &taskColors));

	for (;i < CPUs.size() + Tasks.size(); ++i)
		lamAddGraph(new KsPlot::Graph(&histo, &taskColors,
						      &cpuColors));

	for (i = 1; i < 1000; ++i) {
		it = graphs.begin();

		for (int const &cpu: CPUs)
			(*it++)->fillCPUGraph(stream_id, cpu);

		for (int const &pid: Tasks)
			(*it++)->fillTaskGraph(stream_id, pid);

		/* Clear the screen. */
		glClear(GL_COLOR_BUFFER_BIT);

		/* Draw all graphs. */
		for (auto &g: graphs)
			g->draw();

		glFlush();

		if (!(i % 250))
			zoomIn = !zoomIn;

		if (zoomIn)
			ksmodel_zoom_in(&histo, .01, -1);
		else
			ksmodel_zoom_out(&histo, .01, -1);
	}
}

int main(int argc, char **argv)
{
	struct kshark_context *kshark_ctx(nullptr);
	struct kshark_entry **data(nullptr);
	static char *input_file(nullptr);
	bool shapes(false);
	size_t r, nRows;
	int c, nBins;

	while ((c = getopt(argc, argv, "hsi:")) != -1) {
		switch(c) {
		case 'h':
			usage(argv[0]);
			return 1;
		case 'i':
			input_file = optarg;
			break;
		case 's':
			shapes = true;

		default:
			break;
		}
	}

	auto lamDraw = [&] (void (*func)(void)) {
		/* Initialize Glut. */
		glutInit(&argc, argv);
		makeScene(WINDOW_WIDTH, WINDOW_HEIGHT);

		/* Initialize OpenGL. */
		ksplot_init_opengl(1);
		ksplot_resize_opengl(WINDOW_WIDTH, WINDOW_HEIGHT);

		char *font_file = ksplot_find_font_file("FreeMono", "FreeMonoBold");
		ksplot_init_font(&font, 18, font_file);
		free(font_file);

		/* Display something. */
		glutDisplayFunc(func);
		glutMainLoop();
	};

	if (shapes) {
		/* Draw simple shapes. */
		lamDraw(drawShapes);
		return 0;
	}

	/* Create a new kshark session. */
	if (!kshark_instance(&kshark_ctx))
		return 1;

	/* Open a trace data file produced by trace-cmd. */
	if (!input_file)
		input_file = default_file;

	stream_id = kshark_open(kshark_ctx, input_file);
	if (stream_id < 0) {
		kshark_free(kshark_ctx);
		usage(argv[0]);
		cerr << "\nFailed to open file " << input_file << endl;

		return 1;
	}

	/* Load the content of the file into an array of entries. */
	nRows = kshark_load_entries(kshark_ctx, stream_id, &data);

	/* Initialize the Visualization Model. */
	ksmodel_init(&histo);

	nBins = WINDOW_WIDTH - GRAPH_LABEL_WIDTH - 3 * GRAPH_H_MARGIN;
	ksmodel_set_bining(&histo, nBins, data[0]->ts,
					  data[nRows - 1]->ts);

	/* Fill the model with data and calculate its state. */
	ksmodel_fill(&histo, data, nRows);

	/* Play animated Graph. */
	lamDraw(play);

	/* Free the memory. */
	for (auto &g: graphs)
		delete g;

	for (r = 0; r < nRows; ++r)
		free(data[r]);
	free(data);

	/* Reset (clear) the model. */
	ksmodel_clear(&histo);

	/* Close the file. */
	kshark_close(kshark_ctx, stream_id);

	/* Close the session. */
	kshark_free(kshark_ctx);

	return 0;
}
