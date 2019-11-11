// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

// C
#include <sys/stat.h>
#include <getopt.h>

// Qt
#include <QApplication>

// KernelShark
#include "KsCmakeDef.hpp"
#include "KsMainWindow.hpp"

#define default_input_file (char*)"trace.dat"

static char *prior_input_file, *app_input_file;

void usage(const char *prog)
{
	printf("Usage: %s\n", prog);
	printf("  -h	Display this help message\n");
	printf("  -v	Display version and exit\n");
	printf("  -i	prior input file, default is %s\n", default_input_file);
	printf("  -a	input file to append to the prior\n");
	printf("  -p	register plugin, use plugin name, absolute or relative path\n");
	printf("  -d	register user data input, use absolute or relative path\n");
	printf("  -u	unregister plugin, use plugin name or absolute path\n");
	printf("  -s	import a session\n");
	printf("  -l	import the last session\n");
}

int main(int argc, char **argv)
{
	QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
	QApplication a(argc, argv);

	KsMainWindow ks;

	int c;
	bool fromSession = false;

	while ((c = getopt(argc, argv, "hvi:a:p:d:u:s:l")) != -1) {
		switch(c) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 'v':
			printf("%s - %s\n", basename(argv[0]), KS_VERSION_STRING);
			return 0;

		case 'i':
			prior_input_file = optarg;
			break;

		case 'a':
			app_input_file = optarg;
			break;

		case 'p':
			ks.registerPlugin(QString(optarg));
			break;

		case 'd':
			ks.registerInput(QString(optarg));
			break;

		case 'u':
			ks.unregisterPlugin(QString(optarg));
			break;

		case 's':
			ks.loadSession(QString(optarg));
			fromSession = true;
			break;

		case 'l':
			ks.loadSession(ks.lastSessionFile());
			fromSession = true;
			break;

		default:
			break;
		}
	}

	if (!fromSession) {
		if ((argc - optind) >= 1) {
			if (prior_input_file)
				usage(argv[0]);
			prior_input_file = argv[optind];
		}

		if (!prior_input_file) {
			struct stat st;
			if (stat(default_input_file, &st) == 0)
				prior_input_file = default_input_file;
		}

		if (prior_input_file)
			ks.loadDataFile(QString(prior_input_file));

		if (app_input_file)
			ks.appendDataFile(QString(app_input_file));
	}

	ks.show();
	return a.exec();
}
