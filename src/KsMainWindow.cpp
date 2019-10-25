// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsMainWindow.cpp
 *  @brief   KernelShark GUI main window.
 */

// C
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

// C++11
#include <thread>

// Qt
#include <QMenu>
#include <QFileDialog>
#include <QMenuBar>
#include <QLabel>
#include <QLocalSocket>

// KernelShark
#include "libkshark.h"
#include "libkshark-tepdata.h"
#include "KsCmakeDef.hpp"
#include "KsWidgetsLib.hpp"
#include "KsMainWindow.hpp"
#include "KsAdvFilteringDialog.hpp"

using namespace KsWidgetsLib;

/** Create KernelShark Main window. */
KsMainWindow::KsMainWindow(QWidget *parent)
: QMainWindow(parent),
  _splitter(Qt::Vertical, this),
  _data(this),
  _view(this),
  _graph(this),
  _mState(this),
  _plugins(this),
  _capture(this),
  _captureLocalServer(this),
  _openAction("Open Trace File", this),
  _appendAction("Append Trace File", this),
  _restoreSessionAction("Restore Last Session", this),
  _importSessionAction("Import Session", this),
  _exportSessionAction("Export Session", this),
  _quitAction("Quit", this),
  _importFilterAction("Import Filter", this),
  _exportFilterAction("Export Filter", this),
  _graphFilterSyncCBox(nullptr),
  _listFilterSyncCBox(nullptr),
  _showEventsAction("Show events", this),
  _showTasksAction("Show tasks", this),
  _showCPUsAction("Show CPUs", this),
  _advanceFilterAction("Advance Filtering", this),
  _clearAllFilters("Clear all filters", this),
  _cpuSelectAction("CPUs", this),
  _taskSelectAction("Tasks", this),
  _managePluginsAction("Manage plugins", this),
  _addPluginsAction("Add plugins", this),
  _captureAction("Record", this),
  _addOffcetAction("Add Time Offset", this),
  _colorAction(this),
  _colSlider(this),
  _colorPhaseSlider(Qt::Horizontal, this),
  _fullScreenModeAction("Full Screen Mode", this),
  _aboutAction("About", this),
  _contentsAction("Contents", this),
  _bugReportAction("Report a bug", this),
  _deselectShortcut(this),
  _settings("kernelshark.org", "Kernel Shark") // organization , application
{
	setWindowTitle("Kernel Shark");
	_createActions();
	_createMenus();
	_initCapture();
        _plugins.registerPluginMenues();

	if (geteuid() == 0)
		_rootWarning();

	_splitter.addWidget(&_graph);
	_splitter.addWidget(&_view);
	setCentralWidget(&_splitter);
	connect(&_splitter,	&QSplitter::splitterMoved,
		this,		&KsMainWindow::_splitterMoved);

	_view.setMarkerSM(&_mState);
	connect(&_mState,	&KsDualMarkerSM::markSwitchForView,
		&_view,		&KsTraceViewer::markSwitch);

	_graph.setMarkerSM(&_mState);

	connect(&_mState,	&KsDualMarkerSM::updateGraph,
		&_graph,	&KsTraceGraph::markEntry);

	connect(&_mState,	&KsDualMarkerSM::updateView,
		&_view,		&KsTraceViewer::showRow);

	connect(&_view,		&KsTraceViewer::select,
		&_graph,	&KsTraceGraph::markEntry);

	connect(&_view,		&KsTraceViewer::addTaskPlot,
		&_graph,	&KsTraceGraph::addTaskPlot);

	connect(_graph.glPtr(), &KsGLWidget::updateView,
		&_view,		&KsTraceViewer::showRow);

	connect(&_graph,	&KsTraceGraph::deselect,
		this,		&KsMainWindow::_deselectActive);

	connect(&_view,		&KsTraceViewer::deselect,
		this,		&KsMainWindow::_deselectActive);

	connect(&_data,		&KsDataStore::updateWidgets,
		&_view,		&KsTraceViewer::update);

	connect(&_data,		&KsDataStore::updateWidgets,
		&_graph,	&KsTraceGraph::update);

	connect(&_plugins,	&KsPluginManager::dataReload,
		&_data,		&KsDataStore::reload);

	_deselectShortcut.setKey(Qt::CTRL + Qt::Key_D);
	connect(&_deselectShortcut,	&QShortcut::activated,
		this,			&KsMainWindow::_deselectActive);

	connect(&_mState,	&KsDualMarkerSM::deselectA,
		this,		&KsMainWindow::_deselectA);

	connect(&_mState,	&KsDualMarkerSM::deselectB,
		this,		&KsMainWindow::_deselectB);

	_lastDataFilePath = _settings.value("dataPath").toString();
	_lastConfFilePath = _settings.value("confPath").toString();
	_lastPluginFilePath = _settings.value("pluginPath").toString();

	_resizeEmpty();
}

/** Destroy KernelShark Main window. */
KsMainWindow::~KsMainWindow()
{
	kshark_context *kshark_ctx(nullptr);
	QString file = lastSessionFile();

	if (!file.isEmpty()) {
		QByteArray fileBA = file.toLocal8Bit();

		_updateSession();
		kshark_save_config_file(fileBA.data(),
					_session.getConfDocPtr());
	}

	/*
	 * Do not save the settings if KernelShark is running with Root
	 * privileges. Otherwise the configuration file will be owned by Root.
	 */
	if (geteuid() != 0) {
		_settings.setValue("dataPath", _lastDataFilePath);
		_settings.setValue("confPath", _lastConfFilePath);
		_settings.setValue("pluginPath", _lastPluginFilePath);
	}

	_data.clear();

	/*
	 * Do not show error messages if the "capture" process is still
	 * running (Capture dialog is not closed).
	 */
	if (_capture.state() != QProcess::NotRunning) {
		disconnect(_captureErrorConnection);
		_capture.close();
		_capture.waitForFinished();
	}

	if (kshark_instance(&kshark_ctx))
		kshark_free(kshark_ctx);
}

/**
 * Reimplemented event handler used to update the geometry of the window on
 * resize events.
 */
void KsMainWindow::resizeEvent(QResizeEvent* event)
{
	QMainWindow::resizeEvent(event);

	_session.saveMainWindowSize(*this);
	_session.saveSplitterSize(_splitter);
}

void KsMainWindow::_createActions()
{
	/* File menu */
	_openAction.setIcon(QIcon::fromTheme("document-open"));
	_openAction.setShortcut(tr("Ctrl+O"));
	_openAction.setStatusTip("Open an existing data file");

	connect(&_openAction,	&QAction::triggered,
		this,		&KsMainWindow::_open);

	_appendAction.setIcon(QIcon::fromTheme("document-open"));
	_appendAction.setShortcut(tr("Ctrl+A"));
	_appendAction.setStatusTip("Append an existing data file");

	connect(&_appendAction,	&QAction::triggered,
		this,		&KsMainWindow::_append);

	_restoreSessionAction.setIcon(QIcon::fromTheme("document-open-recent"));
	connect(&_restoreSessionAction,	&QAction::triggered,
		this,			&KsMainWindow::_restoreSession);

	_importSessionAction.setIcon(QIcon::fromTheme("document-send"));
	_importSessionAction.setStatusTip("Load a session");

	connect(&_importSessionAction,	&QAction::triggered,
		this,			&KsMainWindow::_importSession);

	_exportSessionAction.setIcon(QIcon::fromTheme("document-revert"));
	_exportSessionAction.setStatusTip("Export this session");

	connect(&_exportSessionAction,	&QAction::triggered,
		this,			&KsMainWindow::_exportSession);

	_quitAction.setIcon(QIcon::fromTheme("window-close"));
	_quitAction.setShortcut(tr("Ctrl+Q"));
	_quitAction.setStatusTip("Exit KernelShark");

	connect(&_quitAction,	&QAction::triggered,
		this,		&KsMainWindow::close);

	/* Filter menu */
	_importFilterAction.setIcon(QIcon::fromTheme("document-send"));
	_importFilterAction.setStatusTip("Load a filter");

	connect(&_importFilterAction,	&QAction::triggered,
		this,			&KsMainWindow::_importFilter);

	_exportFilterAction.setIcon(QIcon::fromTheme("document-revert"));
	_exportFilterAction.setStatusTip("Export a filter");

	connect(&_exportFilterAction,	&QAction::triggered,
		this,			&KsMainWindow::_exportFilter);

	connect(&_showEventsAction,	&QAction::triggered,
		this,			&KsMainWindow::_showEvents);

	connect(&_showTasksAction,	&QAction::triggered,
		this,			&KsMainWindow::_showTasks);

	connect(&_showCPUsAction,	&QAction::triggered,
		this,			&KsMainWindow::_showCPUs);

	connect(&_advanceFilterAction,	&QAction::triggered,
		this,			&KsMainWindow::_advancedFiltering);

	connect(&_clearAllFilters,	&QAction::triggered,
		this,			&KsMainWindow::_clearFilters);

	/* Plot menu */
	connect(&_cpuSelectAction,	&QAction::triggered,
		this,			&KsMainWindow::_cpuSelect);

	connect(&_taskSelectAction,	&QAction::triggered,
		this,			&KsMainWindow::_taskSelect);

	/* Tools menu */
	_managePluginsAction.setShortcut(tr("Ctrl+P"));
	_managePluginsAction.setIcon(QIcon::fromTheme("preferences-system"));
	_managePluginsAction.setStatusTip("Manage plugins");

	connect(&_managePluginsAction,	&QAction::triggered,
		this,			&KsMainWindow::_pluginSelect);

	_addPluginsAction.setIcon(QIcon::fromTheme("applications-engineering"));
	_addPluginsAction.setStatusTip("Add plugins");

	connect(&_addPluginsAction,	&QAction::triggered,
		this,			&KsMainWindow::_pluginAdd);

	_captureAction.setIcon(QIcon::fromTheme("media-record"));
	_captureAction.setShortcut(tr("Ctrl+R"));
	_captureAction.setStatusTip("Capture trace data");

	connect(&_captureAction,	&QAction::triggered,
		this,			&KsMainWindow::_record);

	connect(&_addOffcetAction,	&QAction::triggered,
		this,			&KsMainWindow::_offset);

	_colorPhaseSlider.setMinimum(20);
	_colorPhaseSlider.setMaximum(180);
	_colorPhaseSlider.setValue(KsPlot::Color::getRainbowFrequency() * 100);
	_colorPhaseSlider.setFixedWidth(FONT_WIDTH * 15);

	connect(&_colorPhaseSlider,	&QSlider::valueChanged,
		this,			&KsMainWindow::_setGraphColorPhase);

	/*
	 * Updating the colors of the table can be slow. Do this only when
	 * the slider is released.
	 */
	connect(&_colorPhaseSlider,	&QSlider::sliderReleased,
		&_view,			&KsTraceViewer::loadColors);

	_colSlider.setLayout(new QHBoxLayout);
	_colSlider.layout()->addWidget(new QLabel("Color scheme", this));
	_colSlider.layout()->addWidget(&_colorPhaseSlider);
	_colorAction.setDefaultWidget(&_colSlider);

	_fullScreenModeAction.setIcon(QIcon::fromTheme("view-fullscreen"));
	_fullScreenModeAction.setShortcut(tr("Ctrl+Shift+F"));
	_fullScreenModeAction.setStatusTip("Full Screen Mode");

	connect(&_fullScreenModeAction,	&QAction::triggered,
		this,			&KsMainWindow::_changeScreenMode);

	/* Help menu */
	_aboutAction.setIcon(QIcon::fromTheme("help-about"));

	connect(&_aboutAction,		&QAction::triggered,
		this,			&KsMainWindow::_aboutInfo);

	_contentsAction.setIcon(QIcon::fromTheme("help-contents"));
	connect(&_contentsAction,	&QAction::triggered,
		this,			&KsMainWindow::_contents);

	connect(&_bugReportAction,	&QAction::triggered,
		this,			&KsMainWindow::_bugReport);
}

void KsMainWindow::_createMenus()
{
	QMenu *file, *sessions, *filter, *plots, *tools, *help;
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	/* File menu */
	file = menuBar()->addMenu("File");
	file->addAction(&_openAction);
	file->addAction(&_appendAction);

	sessions = file->addMenu("Sessions");
	sessions->setIcon(QIcon::fromTheme("document-properties"));
	sessions->addAction(&_restoreSessionAction);
	sessions->addAction(&_importSessionAction);
	sessions->addAction(&_exportSessionAction);
	file->addAction(&_quitAction);

	/* Filter menu */
	filter = menuBar()->addMenu("Filter");

	connect(filter, 		&QMenu::aboutToShow,
		this,			&KsMainWindow::_updateFilterMenu);

	filter->addAction(&_importFilterAction);
	filter->addAction(&_exportFilterAction);

	/*
	 * Set the default filter mask. Filter will apply to both View and
	 * Graph.
	 */
	kshark_ctx->filter_mask =
		KS_TEXT_VIEW_FILTER_MASK | KS_GRAPH_VIEW_FILTER_MASK;

	kshark_ctx->filter_mask |= KS_EVENT_VIEW_FILTER_MASK;

	_graphFilterSyncCBox =
		KsUtils::addCheckBoxToMenu(filter, "Apply filters to Graph");
	_graphFilterSyncCBox->setChecked(true);

	connect(_graphFilterSyncCBox,	&QCheckBox::stateChanged,
		this,			&KsMainWindow::_graphFilterSync);

	_listFilterSyncCBox =
		KsUtils::addCheckBoxToMenu(filter, "Apply filters to List");
	_listFilterSyncCBox->setChecked(true);

	connect(_listFilterSyncCBox,	&QCheckBox::stateChanged,
		this,			&KsMainWindow::_listFilterSync);

	filter->addAction(&_showEventsAction);
	filter->addAction(&_showTasksAction);
	filter->addAction(&_showCPUsAction);
	filter->addAction(&_advanceFilterAction);
	filter->addAction(&_clearAllFilters);

	/* Plot menu */
	plots = menuBar()->addMenu("Plots");
	plots->addAction(&_cpuSelectAction);
	plots->addAction(&_taskSelectAction);

	/* Tools menu */
	tools = menuBar()->addMenu("Tools");
	tools->addAction(&_managePluginsAction);
	tools->addAction(&_addPluginsAction);
	tools->addAction(&_captureAction);
	tools->addAction(&_addOffcetAction);
	tools->addSeparator();
	tools->addAction(&_colorAction);
	tools->addAction(&_fullScreenModeAction);

	/* Help menu */
	help = menuBar()->addMenu("Help");
	help->addAction(&_aboutAction);
	help->addAction(&_contentsAction);
	help->addAction(&_bugReportAction);
}

void KsMainWindow::addPluginMenu(QString place, pluginActionFunc func)
{
	QStringList dialogPath = place.split("/");
	QAction *pluginAction;

	auto lamAddMenu = [this, func] () {
		func(this);
	};

	for (auto &m:  menuBar()->findChildren<QMenu*>()) {
		if(dialogPath[0] == m->menuAction()->text()) {
			pluginAction = new QAction(dialogPath[1], this);
			m->addAction(pluginAction);

			connect(pluginAction,	&QAction::triggered,
				lamAddMenu);
		}
	}
}

void KsMainWindow::_open()
{
	QString fileName;

	fileName = KsUtils::getFile(this, "Open File",
				    "trace-cmd files (*.dat);;All files (*)",
				    _lastDataFilePath);

	if (!fileName.isEmpty())
		loadDataFile(fileName);
}

QString KsMainWindow::_getCacheDir()
{
	QString dir;

	auto lamMakePath = [&] (bool ask) {
		if (ask) {
			QMessageBox::StandardButton reply;
			QString err("KernelShark cache directory not found!\n");
			QString question =
				QString("Do you want to create %1").arg(dir);

			reply = QMessageBox::question(this, "KernelShark",
						      err + question,
						      QMessageBox::Yes |
						      QMessageBox::No);

			if (reply == QMessageBox::No) {
				dir.clear();
				return;
			}
		}

		QDir().mkpath(dir);
	};

	dir = getenv("KS_USER_CACHE_DIR");
	if (!dir.isEmpty()) {
		if (!QDir(dir).exists())
			lamMakePath(true);
	} else {
		auto appCachePath = QStandardPaths::GenericCacheLocation;
		dir = QStandardPaths::writableLocation(appCachePath);
		dir += "/kernelshark";

		if (!QDir(dir).exists())
			lamMakePath(false);
	}

	return dir;
}

/** Get the description file of the last session. */
QString KsMainWindow::lastSessionFile()
{
	QString file;

	file = _getCacheDir();
	if (!file.isEmpty())
		file += "/lastsession.json";

	return file;
}

void KsMainWindow::_append()
{
	QString fileName = KsUtils::getFile(this, "Append File",
					    "trace-cmd files (*.dat);;Text files (*.txt);;All files (*)",
					    _lastDataFilePath);

	if (!fileName.isEmpty())
		appendDataFile(fileName);
}

void KsMainWindow::_restoreSession()
{
	loadSession(lastSessionFile());
}

void KsMainWindow::_importSession()
{
	QString fileName;

	fileName = KsUtils::getFile(this, "Import Session",
				    "Kernel Shark Config files (*.json);;",
				    _lastConfFilePath);

	if (fileName.isEmpty())
		return;

	loadSession(fileName);
}

void KsMainWindow::_updateSession()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	_session.saveVisModel(_graph.glPtr()->model()->histo());
	_session.saveDataStreams(kshark_ctx);
	_session.saveGraphs(kshark_ctx, _graph);
	_session.saveDualMarker(&_mState);
	_session.saveTable(_view);
	_session.saveColorScheme();
	_session.savePlugins(_plugins);
}

void KsMainWindow::_exportSession()
{
	QString fileName;

	fileName = KsUtils::getSaveFile(this, "Export Filter",
					"Kernel Shark Config files (*.json);;",
					".json",
					_lastConfFilePath);
	if (fileName.isEmpty())
		return;

	_updateSession();
	_session.exportToFile(fileName);
}

void KsMainWindow::_filterSyncCBoxUpdate(kshark_context *kshark_ctx)
{
	if (kshark_ctx->filter_mask & KS_TEXT_VIEW_FILTER_MASK)
		_listFilterSyncCBox->setChecked(true);
	else
		_listFilterSyncCBox->setChecked(false);

	if (kshark_ctx->filter_mask &
	    (KS_GRAPH_VIEW_FILTER_MASK | KS_EVENT_VIEW_FILTER_MASK))
		_graphFilterSyncCBox->setChecked(true);
	else
		_graphFilterSyncCBox->setChecked(false);
}

void KsMainWindow::_updateFilterMenu()
{
	kshark_context *kshark_ctx(nullptr);

	if (kshark_instance(&kshark_ctx))
		_filterSyncCBoxUpdate(kshark_ctx);
}

void KsMainWindow::_importFilter()
{
	kshark_context *kshark_ctx(nullptr);
	QString fileName;

	if (!kshark_instance(&kshark_ctx))
		return;

	fileName = KsUtils::getFile(this, "Import Filter",
				    "Kernel Shark Config files (*.json);;",
				    _lastConfFilePath);

	if (fileName.isEmpty())
		return;

	_session.loadFilters(kshark_ctx, fileName, &_data);
}

void KsMainWindow::_exportFilter()
{
	kshark_context *kshark_ctx(nullptr);
	QString fileName;

	if (!kshark_instance(&kshark_ctx))
		return;

	fileName = KsUtils::getSaveFile(this, "Export Filter",
					"Kernel Shark Config files (*.json);;",
					".json",
					_lastConfFilePath);

	if (fileName.isEmpty())
		return;

	_session.saveFilters(kshark_ctx, fileName);
}

void KsMainWindow::_listFilterSync(int state)
{
	KsUtils::listFilterSync(state);
	_data.update();
}

void KsMainWindow::_graphFilterSync(int state)
{
	KsUtils::graphFilterSync(state);
	_data.update();
}

void KsMainWindow::_showEvents()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	KsCheckBoxWidget *events_cb;
	KsCheckBoxDialog *dialog;
	kshark_data_stream *stream;
	int *streamIds, *eventIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		stream = kshark_ctx->stream[streamIds[i]];
		events_cb = new KsEventsCheckBoxWidget(stream, this);
		cbds.append(events_cb);

		if (!stream->show_event_filter ||
		    !stream->show_event_filter->count) {
		    events_cb->setDefault(true);
		} else {
			/*
			 * The event filter contains IDs. Make this visible in
			 * the CheckBox Widget.
			 */

			eventIds = kshark_get_all_event_ids(stream);
			QVector<int> v(stream->n_events, false);
			for (int i = 0; i < stream->n_events; ++i) {
				if (kshark_hash_id_find(stream->show_event_filter,
							  eventIds[i]))
					v[i] = true;
			}

			free(eventIds);
			events_cb->set(v);
		}
	}

	free(streamIds);
	dialog = new KsCheckBoxDialog(cbds, this);

	connect(dialog,		&KsCheckBoxDialog::apply,
		&_data,		&KsDataStore::applyPosEventFilter);

	dialog->show();
}

void KsMainWindow::_showTasks()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	kshark_data_stream *stream;
	KsCheckBoxWidget *tasks_cbd;
	KsCheckBoxDialog *dialog;
	int *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
			stream = kshark_ctx->stream[streamIds[i]];
		tasks_cbd = new KsTasksCheckBoxWidget(stream, true, this);
		cbds.append(tasks_cbd);

		if (!stream->show_task_filter ||
		    !stream->show_task_filter->count) {
			tasks_cbd->setDefault(true);
		} else {
			QVector<int> pids = KsUtils::getPidList(streamIds[i]);
			int nPids = pids.count();
			QVector<int> v(nPids, false);

			for (int i = 0; i < nPids; ++i) {
				if (kshark_hash_id_find(stream->show_task_filter,
							  pids[i]))
					v[i] = true;
			}

			tasks_cbd->set(v);
		}
	}

	free(streamIds);
	dialog = new KsCheckBoxDialog(cbds, this);

	connect(dialog,		&KsCheckBoxDialog::apply,
		&_data,		&KsDataStore::applyPosTaskFilter);

	dialog->show();
}

void KsMainWindow::_hideTasks()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	kshark_data_stream *stream;
	KsCheckBoxWidget *tasks_cbd;
	KsCheckBoxDialog *dialog;
	int *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		stream = kshark_ctx->stream[streamIds[i]];
		tasks_cbd = new KsTasksCheckBoxWidget(stream, false, this);
		cbds.append(tasks_cbd);

		if (!stream->hide_task_filter ||
		    !stream->hide_task_filter->count) {
			tasks_cbd->setDefault(false);
		} else {
			QVector<int> pids = KsUtils::getPidList(streamIds[i]);
			int nPids = pids.count();
			QVector<int> v(nPids, false);

			for (int i = 0; i < nPids; ++i) {
				if (kshark_hash_id_find(stream->hide_task_filter,
							  pids[i]))
					v[i] = true;
			}

			tasks_cbd->set(v);
		}
	}

	free(streamIds);
	dialog = new KsCheckBoxDialog(cbds, this);

	connect(dialog,		&KsCheckBoxDialog::apply,
		&_data,		&KsDataStore::applyNegTaskFilter);

	dialog->show();
}

void KsMainWindow::_showCPUs()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	kshark_data_stream *stream;
	KsCheckBoxWidget *cpus_cbd;
	KsCheckBoxDialog *dialog;
	int *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		stream = kshark_ctx->stream[streamIds[i]];
		cpus_cbd = new KsCPUCheckBoxWidget(stream, this);
		cbds.append(cpus_cbd);

		if (!stream->show_cpu_filter ||
		    !stream->show_cpu_filter->count) {
			cpus_cbd->setDefault(true);
		} else {
			QVector<int> v(stream->n_cpus, false);
			for (int i = 0; i < stream->n_cpus; ++i) {
				if (kshark_hash_id_find(stream->show_cpu_filter, i))
					v[i] = true;
			}

			cpus_cbd->set(v);
		}
	}

	free(streamIds);
	dialog = new KsCheckBoxDialog(cbds, this);

	connect(dialog,		&KsCheckBoxDialog::apply,
		&_data,		&KsDataStore::applyPosCPUFilter);

	dialog->show();
}

void KsMainWindow::_hideCPUs()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	kshark_data_stream *stream;
	KsCheckBoxWidget *cpus_cbd;
	KsCheckBoxDialog *dialog;
	int *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		stream = kshark_ctx->stream[streamIds[i]];
		cpus_cbd = new KsCPUCheckBoxWidget(stream, this);
		cbds.append(cpus_cbd);

		if (!stream->hide_cpu_filter ||
		    !stream->hide_cpu_filter->count) {
			cpus_cbd->setDefault(false);
		} else {
			QVector<int> v(stream->n_cpus, false);
			for (int i = 0; i < stream->n_cpus; ++i) {
				if (kshark_hash_id_find(stream->hide_cpu_filter, i))
					v[i] = true;
			}

			cpus_cbd->set(v);
		}
	}

	free(streamIds);
	dialog = new KsCheckBoxDialog(cbds, this);

	connect(dialog,		&KsCheckBoxDialog::apply,
		&_graph,	&KsTraceGraph::cpuReDraw);

	dialog->show();
}

void KsMainWindow::_advancedFiltering()
{
	KsAdvFilteringDialog *dialog;

	dialog = new KsAdvFilteringDialog(this);
	connect(dialog,		&KsAdvFilteringDialog::dataReload,
		&_data,		&KsDataStore::reload);

	dialog->show();
}

void KsMainWindow::_clearFilters()
{
	_data.clearAllFilters();
}

void KsMainWindow::_cpuSelect()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	kshark_data_stream *stream;
	KsCheckBoxWidget *cpus_cbd;
	KsCheckBoxDialog *dialog;
	int *streamIds, sd, nCPUs;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		stream = kshark_ctx->stream[streamIds[i]];
		cpus_cbd = new KsCPUCheckBoxWidget(stream, this);
		cbds.append(cpus_cbd);

		nCPUs = stream->n_cpus;
		if (nCPUs == _graph.glPtr()->cpuGraphCount(sd)) {
			cpus_cbd->setDefault(true);
		} else {
			QVector<int> v(nCPUs, false);
			for (auto const &cpu: _graph.glPtr()->_streamPlots[sd]._cpuList)
				v[cpu] = true;

			cpus_cbd->set(v);
		}
	}

	free(streamIds);
	dialog = new KsCheckBoxDialog(cbds, this);

	connect(dialog,		&KsCheckBoxDialog::apply,
		&_graph,	&KsTraceGraph::cpuReDraw);

	dialog->show();
}

void KsMainWindow::_taskSelect()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	kshark_data_stream *stream;
	KsCheckBoxWidget *tasks_cbd;
	KsCheckBoxDialog *dialog;
	int *streamIds, sd, nPids;
	QVector<int> pids;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		stream = kshark_ctx->stream[streamIds[i]];
		tasks_cbd = new KsTasksCheckBoxWidget(stream, true, this);
		cbds.append(tasks_cbd);

		pids = KsUtils::getPidList(sd);
		nPids = pids.count();
		if (nPids == _graph.glPtr()->taskGraphCount(sd)) {
			tasks_cbd->setDefault(true);
		} else {
			QVector<int> v(nPids, false);
			for (int i = 0; i < nPids; ++i) {
				QVector<int> plots =
					_graph.glPtr()->_streamPlots[sd]._taskList;
				for (auto const &pid: plots) {
					if (pids[i] == pid) {
						v[i] = true;
						break;
					}
				}
			}

			tasks_cbd->set(v);
		}
	}

	free(streamIds);
	dialog = new KsCheckBoxDialog(cbds, this);

	connect(dialog,		&KsCheckBoxDialog::apply,
		&_graph,	&KsTraceGraph::taskReDraw);

	dialog->show();
}

void KsMainWindow::_pluginSelect()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<KsCheckBoxWidget *> cbds;
	KsCheckBoxWidget *plugin_cbd;
	KsCheckBoxDialog *dialog;
	int *streamIds, sd;
	QStringList plgList;

	if (!kshark_instance(&kshark_ctx))
		return;

	plgList = _plugins.getPluginList();

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		plugin_cbd = new KsPluginCheckBoxWidget(sd, plgList, this);
		plugin_cbd->set(_plugins.getRegisteredPlugins(sd));
		cbds.append(plugin_cbd);
	}

	free(streamIds);
	dialog = new KsPluginsCheckBoxDialog(cbds, &_data, this);
	dialog->applyStatus();

	connect(dialog,		&KsCheckBoxDialog::apply,
		this,		&KsMainWindow::_pluginUpdate);

	dialog->show();

	_graph.update(&_data);
}

void KsMainWindow::_pluginUpdate(int sd, QVector<int> pluginStates)
{
	kshark_context *kshark_ctx(nullptr);
	int *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	_plugins.updatePlugins(sd, pluginStates);
	if (sd == streamIds[kshark_ctx->n_streams - 1]) {
		/* This is the last stream, Reload all data. */
		_data.reload();
	}

	free(streamIds);
}

void KsMainWindow::_pluginAdd()
{
	QStringList fileNames;

	fileNames = KsUtils::getFiles(this, "Add KernelShark plugins",
				      "KernelShark Plugins (*.so);;",
				      _lastPluginFilePath);

	if (!fileNames.isEmpty())
		_plugins.addPlugins(fileNames);

	_graph.update(&_data);
}

void KsMainWindow::_record()
{
#ifndef DO_AS_ROOT

	QErrorMessage *em = new QErrorMessage(this);
	QString message;

	message = "Record is currently not supported.";
	message += " Install \"pkexec\" and then do:<br>";
	message += " cd build <br> sudo ./cmake_uninstall.sh <br>";
	message += " ./cmake_clean.sh <br> cmake .. <br> make <br>";
	message += " sudo make install";

	em->showMessage(message);
	qCritical() << "ERROR: " << message;

	return;

#endif

	_capture.start();
}

void KsMainWindow::_offset()
{
	KsTimeOffsetDialog *dialog = new KsTimeOffsetDialog(this);

	auto lamApplyOffset = [&] (int sd, double ms) {
		_data.setClockOffset(sd, ms * 1000);
		_graph.update(&_data);
	};

	connect(dialog, &KsTimeOffsetDialog::apply, lamApplyOffset);
}

void KsMainWindow::_setGraphColorPhase(int f)
{
	KsPlot::Color::setRainbowFrequency(f / 100.);
	_graph.glPtr()->loadColors();
	_graph.glPtr()->model()->update();
}

void KsMainWindow::_changeScreenMode()
{
	if (isFullScreen()) {
		_fullScreenModeAction.setText("Full Screen Mode");
		_fullScreenModeAction.setIcon(QIcon::fromTheme("view-fullscreen"));
		showNormal();
	} else {
		_fullScreenModeAction.setText("Exit Full Screen Mode");
		_fullScreenModeAction.setIcon(QIcon::fromTheme("view-restore"));
		showFullScreen();
	}
}

void KsMainWindow::_aboutInfo()
{
	KsMessageDialog *message;
	QString text;

	text.append(" KernelShark\n\n version: ");
	text.append(KS_VERSION_STRING);
	text.append("\n");

	message = new KsMessageDialog(text);
	message->setWindowTitle("About");
	message->show();
}

void KsMainWindow::_contents()
{
	QDesktopServices::openUrl(QUrl("http://kernelshark.org/",
				  QUrl::TolerantMode));
}

void KsMainWindow::_bugReport()
{
	QUrl bugs("https://bugzilla.kernel.org/buglist.cgi?component=Trace-cmd%2FKernelshark&product=Tools&resolution=---",
		  QUrl::TolerantMode);

	QDesktopServices::openUrl(bugs);
}

void KsMainWindow::_load(const QString& fileName, bool append)
{
	QString pbLabel("Loading    ");
	bool loadDone = false;
	struct stat st;
	double shift;
	int ret, sd;

	ret = stat(fileName.toStdString().c_str(), &st);
	if (ret != 0) {
		QString text("Unable to find file ");

		text.append(fileName);
		text.append(".");
		_error(text, "loadDataErr1", true, true);

		return;
	}

	qInfo() << "Loading " << fileName;

	if (append) {
		bool ok;
		shift = QInputDialog::getDouble(this, tr("Append Trace file"),
						      tr("Offset [usec]:"), 0,
						      INT_MIN, INT_MAX, 1, &ok);
		if (ok)
			shift *= 1000.;
		else
			shift = 0.;
	}

	if (fileName.size() < 40) {
		pbLabel += fileName;
	} else {
		pbLabel += "...";
		pbLabel += fileName.mid(fileName.size() - 37, 37);
	}

	setWindowTitle("Kernel Shark");
	KsWidgetsLib::KsProgressBar pb(pbLabel);
	QApplication::processEvents();

	_view.reset();
	_graph.reset();

	auto lamLoadJob = [&, this] () {
		sd = _data.loadDataFile(fileName);
		loadDone = true;
	};

	auto lamAppendJob = [&, this] () {
		sd = _data.appendDataFile(fileName, shift);
		loadDone = true;
	};

	std::thread job;
	if (append) {
		job = std::thread(lamAppendJob);
	} else {
		job = std::thread(lamLoadJob);
	}

	for (int i = 0; i < 160; ++i) {
		/*
		 * TODO: The way this progress bar gets updated here is a pure
		 * cheat. See if this can be implemented better.
		*/
		if (loadDone)
			break;

		pb.setValue(i);
		usleep(150000);
	}

	job.join();

	if (!_data.size()) {
		QString text("File ");

		text.append(fileName);
		text.append(" contains no data.");
		_error(text, "loadDataErr2", true, true);

		return;
	}

	_plugins.addStream(sd);
	pb.setValue(165);

	_view.loadData(&_data);
	pb.setValue(180);

	_graph.loadData(&_data);
	pb.setValue(195);
}

/** Load trace data for file. */
void KsMainWindow::loadDataFile(const QString& fileName)
{
	_mState.reset();
	_load(fileName, false);
	setWindowTitle("Kernel Shark (" + fileName + ")");
}

/** Append trace data for file. */
void KsMainWindow::appendDataFile(const QString& fileName)
{
	_load(fileName, true);
}

void KsMainWindow::_error(const QString &mesg, const QString &errCode,
			  bool resize, bool unloadPlugins)
{
	QErrorMessage *em = new QErrorMessage(this);
	QString text = mesg;
	QString html = mesg;

	if (resize)
		_resizeEmpty();

	if (unloadPlugins)
		_plugins.unloadAll();

	text.replace("<br>", "\n", Qt::CaseInsensitive);
	html.replace("\n", "<br>", Qt::CaseInsensitive);

	qCritical().noquote() << "ERROR: " << text;
	em->showMessage(html, errCode);
	em->exec();
}

/**
 * @brief Load user session.
 *
 * @param fileName: Json file containing the description of the session.
 */
void KsMainWindow::loadSession(const QString &fileName)
{
	kshark_context *kshark_ctx(nullptr);
	bool loadDone = false;
	struct stat st;
	int ret;

	if (!kshark_instance(&kshark_ctx))
		return;

	ret = stat(fileName.toStdString().c_str(), &st);
	if (ret != 0) {
		QString text("Unable to find session file ");

		text.append(fileName);
		text.append("\n");
		_error(text, "loadSessErr0", true, true);

		return;
	}

	KsWidgetsLib::KsProgressBar pb("Loading session settings ...");
	pb.setValue(10);

	if (!_session.importFromFile(fileName)) {
		QString text("Unable to open session description file ");

		text.append(fileName);
		text.append(".\n");
		_error(text, "loadSessErr1", true, true);

		return;
	}

	_session.loadPlugins(kshark_ctx, &_plugins);
	_data.clear();
	pb.setValue(20);

	auto lamLoadJob = [&] (KsDataStore *d) {
		_session.loadDataStreams(kshark_ctx, &_data, &_plugins);
		loadDone = true;
	};

	std::thread job = std::thread(lamLoadJob, &_data);

	for (int i = 0; i < 170; ++i) {
		/*
		 * TODO: The way this progress bar gets updated here is a pure
		 * cheat. See if this can be implemented better.
		*/
		if (loadDone)
			break;

		pb.setValue(i);
		usleep(200000);
	}

	job.join();

	if (!kshark_ctx->n_streams) {
		_plugins.unloadAll();
		return;
	}

	_view.loadData(&_data);
	_graph.loadData(&_data);
	_filterSyncCBoxUpdate(kshark_ctx);
	pb.setValue(175);

	_session.loadSplitterSize(&_splitter);
	_session.loadMainWindowSize(this);
	this->show();
	pb.setValue(180);

	_session.loadDualMarker(&_mState, &_graph);
	_session.loadVisModel(_graph.glPtr()->model());
	_mState.updateMarkers(_data, _graph.glPtr());
	_session.loadGraphs(kshark_ctx, _graph);
	pb.setValue(190);

	_session.loadTable(&_view);
	_colorPhaseSlider.setValue(_session.getColorScheme() * 100);
	_graph.updateGeom();
}

void KsMainWindow::_initCapture()
{
	bool canDoAsRoot(false);

#ifdef DO_AS_ROOT
	canDoAsRoot = true;
#endif

	if (geteuid() && !canDoAsRoot)
		return;

	if (geteuid()) {
		_capture.setProgram("kshark-su-record");
	} else {
		QStringList argv;

		_capture.setProgram("kshark-record");
		argv << QString("-o") << QDir::homePath() + "/trace.dat";
		_capture.setArguments(argv);
	}

	connect(&_capture,	&QProcess::started,
		this,		&KsMainWindow::_captureStarted);

	/*
	 * Using the old Signal-Slot syntax because QProcess::finished has
	 * overloads.
	 */
	connect(&_capture,	SIGNAL(finished(int, QProcess::ExitStatus)),
		this,		SLOT(_captureFinished(int, QProcess::ExitStatus)));

	_captureErrorConnection =
		connect(&_capture,	&QProcess::errorOccurred,
			this,		&KsMainWindow::_captureError);

	connect(&_captureLocalServer,	&QLocalServer::newConnection,
		this,			&KsMainWindow::_readSocket);

}

void KsMainWindow::_captureStarted()
{
	_captureLocalServer.listen("KSCapture");
}

/**
 * If the authorization could not be obtained because the user dismissed
 * the authentication dialog (clicked Cancel), pkexec exits with a return
 * value of 126.
 */
#define PKEXEC_DISMISS_RET	126

void KsMainWindow::_captureFinished(int ret, QProcess::ExitStatus st)
{
	QProcess *capture = (QProcess *)sender();

	_captureLocalServer.close();

	if (ret == PKEXEC_DISMISS_RET) {
		/*
		 * Authorization could not be obtained because the user
		 * dismissed the authentication dialog.
		 */
		return;
	}

	if (ret != 0 && st == QProcess::NormalExit)
		_captureErrorMessage(capture);
}

void KsMainWindow::_captureError(QProcess::ProcessError error)
{
	QProcess *capture = (QProcess *)sender();
	_captureErrorMessage(capture);
}

void KsMainWindow::_captureErrorMessage(QProcess *capture)
{
	QString message = "Capture process failed: ";

	message += capture->errorString();
	message += "<br>Standard Error: ";
	message += capture->readAllStandardError();
	_error(message, "captureFinishedErr", false, false);
}

void KsMainWindow::_readSocket()
{
	QLocalSocket *socket;
	quint32 blockSize;
	QString fileName;

	auto lamSocketError = [&](QString message)
	{
		message = "ERROR from Local Server: " + message;
		_error(message, "readSocketErr", false, false);
	};

	socket = _captureLocalServer.nextPendingConnection();
	if (!socket) {
		lamSocketError("Pending connectio not found!");
		return;
	}

	QDataStream in(socket);
	socket->waitForReadyRead();
	if (socket->bytesAvailable() < (int)sizeof(quint32)) {
		lamSocketError("Message size is corrupted!");
		return;
	};

	in >> blockSize;
	if (socket->bytesAvailable() < blockSize || in.atEnd()) {
		lamSocketError("Message is corrupted!");
		return;
	}

	in >> fileName;
	loadDataFile(fileName);
}

void KsMainWindow::_splitterMoved(int pos, int index)
{
	_session.saveSplitterSize(_splitter);
}

void KsMainWindow::_deselectActive()
{
	_view.clearSelection();
	_mState.activeMarker().remove();
	_mState.updateLabels();
	_graph.glPtr()->model()->update();
}

void KsMainWindow::_deselectA()
{
	if (_mState.getState() == DualMarkerState::A)
		_view.clearSelection();
	else
		_view.passiveMarkerSelectRow(KS_NO_ROW_SELECTED);

	_mState.markerA().remove();
	_mState.updateLabels();
	_graph.glPtr()->model()->update();
}

void KsMainWindow::_deselectB()
{
	if (_mState.getState() == DualMarkerState::B)
		_view.clearSelection();
	else
		_view.passiveMarkerSelectRow(KS_NO_ROW_SELECTED);

	_mState.markerB().remove();
	_mState.updateLabels();
	_graph.glPtr()->model()->update();
}

void KsMainWindow::_rootWarning()
{
	QString cbFlag("noRootWarn");

	if (_settings.value(cbFlag).toBool())
		return;

	QMessageBox warn;
	warn.setText("KernelShark is running with Root privileges.");
	warn.setInformativeText("Continue at your own risk.");
	warn.setIcon(QMessageBox::Warning);
	warn.setStandardButtons(QMessageBox::Close);

	QCheckBox cb("Don't show this message again.");

	auto lamCbChec = [&] (int state) {
		if (state)
			_settings.setValue(cbFlag, true);
	};

	connect(&cb, &QCheckBox::stateChanged, lamCbChec);
	warn.setCheckBox(&cb);
	warn.exec();
}
