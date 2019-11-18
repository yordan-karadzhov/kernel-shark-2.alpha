/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsMainWindow.hpp
 *  @brief   KernelShark GUI main window.
 */

#ifndef _KS_MAINWINDOW_H
#define _KS_MAINWINDOW_H

// Qt
#include <QMainWindow>
#include <QLocalServer>

// KernelShark
#include "KsTraceViewer.hpp"
#include "KsTraceGraph.hpp"
#include "KsWidgetsLib.hpp"
#include "KsPlugins.hpp"
#include "KsSession.hpp"
#include "KsUtils.hpp"

/**
 * The KsMainWindow class provides Main window for the KernelShark GUI.
 */
class KsMainWindow : public QMainWindow
{
	Q_OBJECT
public:
	explicit KsMainWindow(QWidget *parent = nullptr);

	~KsMainWindow();

	void loadDataFile(const QString &fileName);

	void appendDataFile(const QString &fileName);

	void loadSession(const QString &fileName);

	QString lastSessionFile();

	/**
	 * @brief
	 *
	 * @param plugin: can be the name of the plugin or the plugin's library
	 * file (including absolute or relative path).
	 */
	void registerPlugin(const QString &plugin)
	{
		_plugins.registerPlugin(plugin);
	}

	/**
	 * @brief
	 *
	 * @param plugin: can be the name of the plugin or the plugin's library
	 * file (including absolute path).
	 */
	void unregisterPlugin(const QString &plugin)
	{
		_plugins.unregisterPlugin(plugin);
	}

	void registerInput(const QStringList &inputs);

	void resizeEvent(QResizeEvent* event);

	/** Set the Full Screen mode. */
	void setFullScreenMode(bool f) {
		if ((!isFullScreen() && f) || (isFullScreen() && !f) )
			_changeScreenMode();
	}

	void addPluginMenu(QString place, pluginActionFunc action);

	KsTraceGraph *graphPtr() {return &_graph;}

private:
	QSplitter	_splitter;

	/** GUI session. */
	KsSession	_session;

	/** Data Manager. */
	KsDataStore	_data;

	/** Widget for reading and searching in the trace data. */
	KsTraceViewer	_view;

	/** Widget for graphical visualization of the trace data. */
	KsTraceGraph	_graph;

	/** Dual Marker State Machine. */
	KsDualMarkerSM	_mState;

	/** Plugin manager. */
	KsPluginManager	_plugins;

	/** The process used to record trace data. */
	QProcess	_capture;

	/** Local Server used for comunucation with the Capture process. */
	QLocalServer	_captureLocalServer;

	// File menu.
	QAction		_openAction;

	QAction		_appendAction;

	QAction		_restoreSessionAction;

	QAction		_importSessionAction;

	QAction		_exportSessionAction;

	QAction		_quitAction;

	// Filter menu.
	QAction		_importFilterAction;

	QAction		_exportFilterAction;

	QCheckBox	*_graphFilterSyncCBox;

	QCheckBox	*_listFilterSyncCBox;

	QAction		_showEventsAction;

	QAction		_showTasksAction;

	QAction		_showCPUsAction;

	QAction		_advanceFilterAction;

	QAction		_clearAllFilters;

	// Plots menu.
	QAction		_cpuSelectAction;

	QAction		_taskSelectAction;

	// Tools menu.
	QAction		_managePluginsAction;

	QAction		_addPluginsAction;

	QAction		_addUserInputAction;

	QAction		_captureAction;

	QAction		_addOffcetAction;

	QWidgetAction	_colorAction;

	QWidget		_colSlider;

	QSlider		_colorPhaseSlider;

	QAction		_fullScreenModeAction;

	// Help menu.
	QAction		_aboutAction;

	QAction		_contentsAction;

	QAction		_bugReportAction;

	QShortcut	_deselectShortcut;

	QString		_lastDataFilePath, _lastConfFilePath, _lastPluginFilePath;

	QSettings	_settings;

	QMetaObject::Connection		_captureErrorConnection;

	// Status bar.
	KsWidgetsLib::KsWorkInProgress	_workInProgress;

	void _load(const QString& fileName, bool append);

	void _open();

	void _append();

	void _restoreSession();

	void _importSession();

	void _exportSession();

	void _importFilter();

	void _exportFilter();

	void _listFilterSync(int state);

	void _graphFilterSync(int state);

	void _showEvents();

	void _showTasks();

	void _hideTasks();

	void _showCPUs();

	void _hideCPUs();

	void _advancedFiltering();

	void _clearFilters();

	void _cpuSelect();

	void _taskSelect();

	void _virtComboSelect();

	void _pluginSelect();

	void _pluginUpdate(int sd, QVector<int> pluginStates);

	void _pluginAdd();

	void _inputAdd();

	void _record();

	void _offset();

	void _setGraphColorPhase(int);

	void _changeScreenMode();

	void _aboutInfo();

	void _contents();

	void _bugReport();

	void _captureStarted();

	void _captureError(QProcess::ProcessError error);

	void _captureErrorMessage(QProcess *capture);

	void _readSocket();

	void _splitterMoved(int pos, int index);

	void _createActions();

	void _createMenus();

	void _initCapture();

	void _updateSession();

	inline void _resizeEmpty() {resize(SCREEN_WIDTH * .5, FONT_HEIGHT * 3);}

	void _error(const QString &text, const QString &errCode,
		    bool resize, bool unloadPlugins);

	void _deselectActive();

	void _deselectA();

	void _deselectB();

	void _rootWarning();

	void _updateFilterMenu();

	void _filterSyncCBoxUpdate(kshark_context *kshark_ctx);

	QString _getCacheDir();

private slots:
	void _captureFinished(int, QProcess::ExitStatus);
};

#endif // _KS_MAINWINDOW_H
