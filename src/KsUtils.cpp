// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsUtils.cpp
 *  @brief   KernelShark Utils.
 */

// KernelShark
#include "libkshark-plugin.h"
#include "libkshark-tepdata.h"
#include "KsUtils.hpp"
#include "KsWidgetsLib.hpp"

namespace KsUtils {

/**
 * @brief Get a sorteg vector of Task's Pids.
 *
 * @param sd: Data stream identifier.
 */
QVector<int> getPidList(int sd)
{
	kshark_context *kshark_ctx(nullptr);
	int nTasks, *tempPids;
	QVector<int> pids;

	if (!kshark_instance(&kshark_ctx))
		return pids;

	nTasks = kshark_get_task_pids(kshark_ctx, sd, &tempPids);
	for (int r = 0; r < nTasks; ++r) {
		pids.append(tempPids[r]);
	}

	free(tempPids);

	return pids;
}

/** @brief Get a sorted vector of Id values of a filter. */
QVector<int> getFilterIds(kshark_hash_id *filter)
{
	kshark_context *kshark_ctx(nullptr);
	int *cpuFilter, n;
	QVector<int> v;

	if (!kshark_instance(&kshark_ctx))
		return v;

	cpuFilter = kshark_hash_ids(filter);
	n = filter->count;
	for (int i = 0; i < n; ++i)
		v.append(cpuFilter[i]);

	free(cpuFilter);
	return v;
}

/**
 * Set the bit of the filter mask of the kshark session context responsible
 * for the visibility of the events in the Table View.
 */
void listFilterSync(bool state)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	if (state) {
		kshark_ctx->filter_mask |= KS_TEXT_VIEW_FILTER_MASK;
	} else {
		kshark_ctx->filter_mask &= ~KS_TEXT_VIEW_FILTER_MASK;
	}
}

/**
 * Set the bit of the filter mask of the kshark session context responsible
 * for the visibility of the events in the Graph View.
 */
void graphFilterSync(bool state)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	if (state) {
		kshark_ctx->filter_mask |= KS_GRAPH_VIEW_FILTER_MASK;
		kshark_ctx->filter_mask |= KS_EVENT_VIEW_FILTER_MASK;
	} else {
		kshark_ctx->filter_mask &= ~KS_GRAPH_VIEW_FILTER_MASK;
		kshark_ctx->filter_mask &= ~KS_EVENT_VIEW_FILTER_MASK;
	}
}


/**
 * @brief Add a checkbox to a menu.
 *
 * @param menu: Input location for the menu object, to which the checkbox will be added.
 * @param name: The name of the checkbox.
 *
 * @returns The checkbox object;
 */
QCheckBox *addCheckBoxToMenu(QMenu *menu, QString name)
{
	QWidget  *containerWidget = new QWidget(menu);
	containerWidget->setLayout(new QHBoxLayout());
	containerWidget->layout()->setContentsMargins(FONT_WIDTH, FONT_HEIGHT/5,
						      FONT_WIDTH, FONT_HEIGHT/5);
	QCheckBox *checkBox = new QCheckBox(name, menu);
	containerWidget->layout()->addWidget(checkBox);

	QWidgetAction *action = new QWidgetAction(menu);
	action->setDefaultWidget(containerWidget);
	menu->addAction(action);

	return checkBox;
}

/**
 * @brief Simple CPU matching function to be user for data collections.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param e: kshark_entry to be checked.
 * @param sd: Data stream identifier.
 * @param cpu: Matching condition value.
 *
 * @returns True if the CPU of the entry matches the value of "cpu" and
 * 	    the entry is visibility in Graph. Otherwise false.
 */
bool matchCPUVisible(struct kshark_context *kshark_ctx,
		     struct kshark_entry *e, int sd, int *cpu)
{
	return (e->cpu == *cpu &&
		e->stream_id == sd &&
		(e->visible & KS_GRAPH_VIEW_FILTER_MASK));
}

/**
 * @brief Get an elided version of the string that will fit within a label.
 *
 * @param label: Pointer to the label object.
 * @param text: The text to be elided.
 * @param mode: Parameter specifies whether the text is elided on the left,
 *		in the middle, or on the right.
 * @param labelWidth: The desired width of the label.
 */
void setElidedText(QLabel* label, QString text,
		   enum Qt::TextElideMode mode,
		   int labelWidth)
{
	QFontMetrics metrix(label->font());
	QString elidedText;
	int textWidth;

	textWidth = labelWidth - FONT_WIDTH * 3;
	elidedText = metrix.elidedText(text, Qt::ElideRight, textWidth);

	while(labelWidth < STRING_WIDTH(elidedText) + FONT_WIDTH * 5) {
		textWidth -= FONT_WIDTH * 3;
		elidedText = metrix.elidedText(text, mode, textWidth);
	}

	label->setText(elidedText);
}

/**
 * @brief Check if the application runs from its installation location.
 */
bool isInstalled()
{
	QString appPath = QCoreApplication::applicationDirPath();
	QString installPath(_INSTALL_PREFIX);

	installPath += "/bin";
	installPath = QDir::cleanPath(installPath);

	return appPath == installPath;
}

static QString getFileDialog(QWidget *parent,
			     const QString &windowName,
			     const QString &filter,
			     QString &lastFilePath,
			     bool forSave)
{
	QString fileName;

	if (lastFilePath.isEmpty()) {
		lastFilePath = isInstalled() ? QDir::homePath() :
					       QDir::currentPath();
	}

	if (forSave) {
		fileName = QFileDialog::getSaveFileName(parent,
							windowName,
							lastFilePath,
							filter);
	} else {
		fileName = QFileDialog::getOpenFileName(parent,
							windowName,
							lastFilePath,
							filter);
	}

	if (!fileName.isEmpty())
		lastFilePath = QFileInfo(fileName).path();

	return fileName;
}

static QStringList getFilesDialog(QWidget *parent,
				  const QString &windowName,
				  const QString &filter,
				  QString &lastFilePath)
{
	QStringList fileNames;

	if (lastFilePath.isEmpty()) {
		lastFilePath = isInstalled() ? QDir::homePath() :
					       QDir::currentPath();
	}

	fileNames = QFileDialog::getOpenFileNames(parent,
						  windowName,
						  lastFilePath,
						  filter);

	if (!fileNames.isEmpty())
		lastFilePath = QFileInfo(fileNames[0]).path();

	return fileNames;
}

/**
 * @brief Open a standard Qt getFileName dialog and return the name of the
 *	  selected file. Only one file can be selected.
 */
QString getFile(QWidget *parent,
		const QString &windowName,
		const QString &filter,
		QString &lastFilePath)
{
	return getFileDialog(parent, windowName, filter, lastFilePath, false);
}

/**
 * @brief Open a standard Qt getFileName dialog and return the names of the
 *	  selected files. Multiple files can be selected.
 */
QStringList getFiles(QWidget *parent,
		     const QString &windowName,
		     const QString &filter,
		     QString &lastFilePath)
{
	return getFilesDialog(parent, windowName, filter, lastFilePath);
}

/**
 * @brief Open a standard Qt getFileName dialog and return the name of the
 *	  selected file. Only one file can be selected.
 */
QString getSaveFile(QWidget *parent,
		    const QString &windowName,
		    const QString &filter,
		    const QString &extension,
		    QString &lastFilePath)
{
	QString fileName = getFileDialog(parent,
					 windowName,
					 filter,
					 lastFilePath,
					 true);

	if (!fileName.isEmpty() && !fileName.endsWith(extension)) {
		fileName += extension;

		if (QFileInfo(fileName).exists()) {
			if (!KsWidgetsLib::fileExistsDialog(fileName))
				fileName.clear();
		}
	}

	return fileName;
}

/**
 * Separate the command line arguments inside the string taking into account
 * possible shell quoting and new lines.
 */
QStringList splitArguments(QString cmd)
{
	QString::SplitBehavior opt = QString::SkipEmptyParts;
	int i, progress = 0, size;
	QStringList argv;
	QChar quote = 0;

	/* Remove all new lines. */
	cmd.replace("\\\n", " ");

	size = cmd.count();
	auto lamMid = [&] () {return cmd.mid(progress, i - progress);};
	for (i = 0; i < size; ++i) {
		if (cmd[i] == '\\') {
			cmd.remove(i, 1);
			size --;
			continue;
		}

		if (cmd[i] == '\'' || cmd[i] == '"') {
			if (quote.isNull()) {
				argv << lamMid().split(" ", opt);
				quote = cmd[i++];
				progress = i;
			} else if (quote == cmd[i]) {
				argv << lamMid();
				quote = 0;
				progress = ++i;
			}
		}
	}

	argv << cmd.right(size - progress).split(" ", opt);

	return argv;
}

/**
 * @brief Split the ststem name from the actual name of the event itself.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param eventId: Identifier of the Event.
 */
QStringList getTepEvtName(kshark_data_stream *stream, int eventId)
{
	kshark_entry e;

	e.event_id = eventId;
	e.visible = KS_PLUGIN_UNTOUCHED_MASK;
	QString name(stream->interface.get_event_name(stream, &e));

	return name.split('/');
}

/**
 * @brief Get a string to be used as a standard name of a task graph.
 *
 * @param sd: Graph's Data stream identifier.
 * @param pid: Graph's progress Id.
 */
QString taskPlotName(int sd, int pid)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	QString name;

	if (!kshark_instance(&kshark_ctx))
		return {};

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return {};

	name = kshark_comm_from_pid(stream, pid);
	name += "-";
	name += QString("%1").arg(pid);

	return name;
}

}; // KsUtils

/** A stream operator for converting QColor into KsPlot::Color. */
KsPlot::Color& operator <<(KsPlot::Color &thisColor, const QColor &c)
{
	thisColor.set(c.red(), c.green(), c.blue());

	return thisColor;
}

/** A stream operator for converting KsPlot::Color into QColor. */
QColor& operator <<(QColor &thisColor, const KsPlot::Color &c)
{
	thisColor.setRgb(c.r(), c.g(), c.b());

	return thisColor;
}

/** Create a default (empty) KsDataStore. */
KsDataStore::KsDataStore(QWidget *parent)
: QObject(parent),
  _rows(nullptr),
  _dataSize(0)
{}

/** Destroy the KsDataStore object. */
KsDataStore::~KsDataStore()
{}

int KsDataStore::_openDataFile(kshark_context *kshark_ctx,
				const QString &file)
{
	int sd;

	sd = kshark_open(kshark_ctx, file.toStdString().c_str());
	if (sd < 0) {
		qCritical() << "ERROR" << sd << "while loading file " << file;
		return sd;
	}

	return sd;
}

/** Load trace data for file. */
int  KsDataStore::loadDataFile(const QString &file)
{
	kshark_context *kshark_ctx(nullptr);
	ssize_t n;
	int sd;

	if (!kshark_instance(&kshark_ctx))
		return -EFAULT;

	clear();
	unregisterCPUCollections();
	kshark_close_all(kshark_ctx);

	sd = _openDataFile(kshark_ctx, file);
	n = kshark_load_entries(kshark_ctx, sd, &_rows);
	if (n < 0) {
		kshark_close(kshark_ctx, sd);
		return n;
	}

	_dataSize = n;
	registerCPUCollections();

	return sd;
}

/**
 * @brief Append a trace data file to the data-set that is already loaded.
 *	  The clock of the new data will be calibrated in order to be
 *	  compatible with the clock of the prior data.
 *
 * @param file: Trace data file, to be append to the already loaded data.
 * @param offset: The offset in time of the Data stream to be appended.
 */
int KsDataStore::appendDataFile(const QString &file, int64_t offset)
{
	kshark_context *kshark_ctx(nullptr);
	struct kshark_entry **apndRows = NULL;
	struct kshark_entry **mergedRows;
	ssize_t nApnd = 0;
	int sd;

	if (!kshark_instance(&kshark_ctx))
		return -EFAULT;

	unregisterCPUCollections();

	sd = _openDataFile(kshark_ctx, file);

	kshark_ctx->stream[sd]->calib = kshark_offset_calib;
	kshark_ctx->stream[sd]->calib_array = (int64_t *) malloc(sizeof(int64_t));
	*(kshark_ctx->stream[sd]->calib_array) = offset;
	kshark_ctx->stream[sd]->calib_array_size = 1;

	nApnd = kshark_load_entries(kshark_ctx, sd, &apndRows);
	if (nApnd <= 0) {
		QErrorMessage *em = new QErrorMessage();
		em->showMessage(QString("File %1 contains no data.").arg(file));
		em->exec();

		kshark_close(kshark_ctx, sd);
		return nApnd;
	}

	mergedRows = kshark_data_merge(_rows, _dataSize,
				       apndRows, nApnd);

	free(_rows);
	free(apndRows);

	_dataSize += nApnd;
	_rows = mergedRows;

	registerCPUCollections();

	return sd;
}

void KsDataStore::_freeData()
{
	if (_dataSize > 0) {
		for (ssize_t r = 0; r < _dataSize; ++r)
			free(_rows[r]);

		free(_rows);
		_rows = nullptr;
	}

	_dataSize = 0;
}

/** Reload the trace data. */
void KsDataStore::reload()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	_freeData();

	if (kshark_ctx->n_streams == 0)
		return;

	unregisterCPUCollections();

	_dataSize = kshark_load_all_entries(kshark_ctx, &_rows);

	registerCPUCollections();

	emit updateWidgets(this);
}

/** Free the loaded trace data and close the file. */
void KsDataStore::clear()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	_freeData();
	unregisterCPUCollections();
}

/** Update the visibility of the entries (filter). */
void KsDataStore::update()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	unregisterCPUCollections();

	kshark_filter_all_entries(kshark_ctx, _rows, _dataSize);

	registerCPUCollections();

	emit updateWidgets(this);
}

/** Register a collection of visible entries for each CPU. */
void KsDataStore::registerCPUCollections()
{
	kshark_context *kshark_ctx(nullptr);
	int *streamIds, nCPUs, sd;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];

		nCPUs = kshark_ctx->stream[sd]->n_cpus;
		for (int cpu = 0; cpu < nCPUs; ++cpu) {
			kshark_register_data_collection(kshark_ctx,
							_rows, _dataSize,
							KsUtils::matchCPUVisible,
							sd, &cpu, 1,
							0);
		}
	}

	free(streamIds);
}

/** Unregister all CPU collections. */
void KsDataStore::unregisterCPUCollections()
{
	kshark_context *kshark_ctx(nullptr);
	int *streamIds, nCPUs, sd;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];

		nCPUs = kshark_ctx->stream[sd]->n_cpus;
		for (int cpu = 0; cpu < nCPUs; ++cpu) {
			kshark_unregister_data_collection(&kshark_ctx->collections,
							  KsUtils::matchCPUVisible,
							  sd, &cpu, 1);
		}
	}

	free(streamIds);
}

void KsDataStore::_applyIdFilter(int filterId, QVector<int> vec, int sd)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;

	if (!kshark_instance(&kshark_ctx))
		return;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	switch (filterId) {
		case KS_SHOW_EVENT_FILTER:
		case KS_HIDE_EVENT_FILTER:
			kshark_filter_clear(kshark_ctx, sd, KS_SHOW_EVENT_FILTER);
			kshark_filter_clear(kshark_ctx, sd, KS_HIDE_EVENT_FILTER);
			break;
		case KS_SHOW_TASK_FILTER:
		case KS_HIDE_TASK_FILTER:
			kshark_filter_clear(kshark_ctx, sd, KS_SHOW_TASK_FILTER);
			kshark_filter_clear(kshark_ctx, sd, KS_HIDE_TASK_FILTER);
			break;
		case KS_SHOW_CPU_FILTER:
		case KS_HIDE_CPU_FILTER:
			kshark_filter_clear(kshark_ctx, sd, KS_SHOW_CPU_FILTER);
			kshark_filter_clear(kshark_ctx, sd, KS_HIDE_CPU_FILTER);
			break;
		default:
			return;
	}

	for (auto &&val: vec)
		kshark_filter_add_id(kshark_ctx, sd, filterId, val);

	if (!kshark_ctx->n_streams)
		return;

	unregisterCPUCollections();

	/*
	 * If the advanced event filter is set the data has to be reloaded,
	 * because the advanced filter uses tep_records.
	 */
	if (stream->format == KS_TEP_DATA && kshark_tep_filter_is_set(stream))
		reload();
	else
		kshark_filter_stream_entries(kshark_ctx, sd, _rows, _dataSize);

	registerCPUCollections();

	emit updateWidgets(this);
}

/** Apply Show Task filter. */
void KsDataStore::applyPosTaskFilter(int sd, QVector<int> vec)
{
	kshark_context *kshark_ctx(nullptr);
	int nTasks, *pids;

	if (!kshark_instance(&kshark_ctx))
		return;

	nTasks = kshark_get_task_pids(kshark_ctx, sd, &pids);
	free(pids);
	if (vec.count() == nTasks)
		return;

	_applyIdFilter(KS_SHOW_TASK_FILTER, vec, sd);
}

/** Apply Hide Task filter. */
void KsDataStore::applyNegTaskFilter(int sd, QVector<int> vec)
{
	if (!vec.count())
		return;

	_applyIdFilter(KS_HIDE_TASK_FILTER, vec, sd);
}

/** Apply Show Event filter. */
void KsDataStore::applyPosEventFilter(int sd, QVector<int> vec)
{
	_applyIdFilter(KS_SHOW_EVENT_FILTER, vec, sd);
}

/** Apply Hide Event filter. */
void KsDataStore::applyNegEventFilter(int sd, QVector<int> vec)
{
	if (!vec.count())
		return;

	_applyIdFilter(KS_HIDE_EVENT_FILTER, vec, sd);
}

/** Apply Show CPU filter. */
void KsDataStore::applyPosCPUFilter(int sd, QVector<int> vec)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;

	if (!kshark_instance(&kshark_ctx))
		return;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	if (vec.count() == stream->n_cpus)
		return;

	_applyIdFilter(KS_SHOW_CPU_FILTER, vec, sd);
}

/** Apply Hide CPU filter. */
void KsDataStore::applyNegCPUFilter(int sd, QVector<int> vec)
{
	if (!vec.count())
		return;

	_applyIdFilter(KS_HIDE_CPU_FILTER, vec, sd);
}

/** Disable all filters. */
void KsDataStore::clearAllFilters()
{
	kshark_context *kshark_ctx(nullptr);
	int *streamIds, sd;

	if (!kshark_instance(&kshark_ctx) || !kshark_ctx->n_streams)
		return;

	unregisterCPUCollections();

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];

		kshark_filter_clear(kshark_ctx, sd, KS_SHOW_TASK_FILTER);
		kshark_filter_clear(kshark_ctx, sd, KS_HIDE_TASK_FILTER);
		kshark_filter_clear(kshark_ctx, sd, KS_SHOW_EVENT_FILTER);
		kshark_filter_clear(kshark_ctx, sd, KS_HIDE_EVENT_FILTER);
		kshark_filter_clear(kshark_ctx, sd, KS_SHOW_CPU_FILTER);
		kshark_filter_clear(kshark_ctx, sd, KS_HIDE_CPU_FILTER);

		if (kshark_ctx->stream[sd]->format == KS_TEP_DATA)
			kshark_tep_filter_reset(kshark_ctx->stream[sd]);
	}

	kshark_clear_all_filters(kshark_ctx, _rows, _dataSize);

	free(streamIds);

	emit updateWidgets(this);
}

/**
 * @brief Apply constant offset to the timestamps of all entries from a given
 *	  Data stream.
 *
 * @param sd: Data stream identifier.
 * @param offset: The constant offset to be added (in nanosecond).
 */
void KsDataStore::setClockOffset(int sd, int64_t offset)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	if (!kshark_get_data_stream(kshark_ctx, sd))
		return;

	unregisterCPUCollections();
	kshark_set_clock_offset(kshark_ctx, _rows, _dataSize, sd, offset);
	registerCPUCollections();
}

/**
 * @brief Create Plugin Manager. Use list of plugins declared in the
 *	  CMake-generated header file.
 */
KsPluginManager::KsPluginManager(QWidget *parent)
: QObject(parent)
{
	kshark_context *kshark_ctx(nullptr);
	_parsePluginList();

	if (!kshark_instance(&kshark_ctx))
		return;

	registerFromList(kshark_ctx);
	qInfo() << _registeredKsPlugins;
}

KsPluginManager::~KsPluginManager()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	unregisterFromList(kshark_ctx);
}

/** Parse the plugin list declared in the CMake-generated header file. */
void KsPluginManager::_parsePluginList()
{
	kshark_context *kshark_ctx(nullptr);
	int nPlugins, *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	_ksPluginList = KsUtils::getPluginList();
	nPlugins = _ksPluginList.count();
	_registeredKsPlugins[-1].resize(nPlugins);

	for (int i = 0; i < nPlugins; ++i) {
		if (_ksPluginList[i].contains(" default", Qt::CaseInsensitive)) {
			_ksPluginList[i].remove(" default",
						Qt::CaseInsensitive);
			_registeredKsPlugins[-1][i] = true;
		} else {
			_registeredKsPlugins[-1][i] = false;
		}
	}

	for (int j = 0; j < kshark_ctx->n_streams; ++j)
		_registeredKsPlugins[streamIds[j]] = _registeredKsPlugins[-1];

	free(streamIds);
}

/**
 * Register the plugins by using the information in "_ksPluginList" and
 * "_registeredKsPlugins".
 */
void KsPluginManager::registerFromList(kshark_context *kshark_ctx)
{
	qInfo() << "registerFromList" << _ksPluginList;
	auto lamRegBuiltIn = [&kshark_ctx, this](const QString &plugin)
	{
		char *lib;
		int n;

		lib = _pluginLibFromName(plugin, n);
		if (n <= 0)
			return;

		qInfo() << "reg" << lib;
		kshark_register_plugin(kshark_ctx, lib);
		free(lib);
	};

	auto lamRegUser = [&kshark_ctx](const QString &plugin)
	{
		std::string lib = plugin.toStdString();
		kshark_register_plugin(kshark_ctx, lib.c_str());
	};

	/*
	 * We want the order inside the list to be the same as in the vector,
	 * but we always add to the beginning of the list. This mean that we
	 * need a reverse loop.
	 */
	auto reverse = [] (QStringList l) {
		QStringList r = l;
		std::reverse(r.begin(), r.end());
		return r;
	};

	for (auto const &p: reverse(_ksPluginList))
		lamRegBuiltIn(p);

	for (auto const &p: reverse(_userPluginList))
		lamRegUser(p);
}

/**
 * Unegister the plugins by using the information in "_ksPluginList" and
 * "_registeredKsPlugins".
 */
void KsPluginManager::unregisterFromList(kshark_context *kshark_ctx)
{
	auto lamUregBuiltIn = [&kshark_ctx, this](const QString &plugin)
	{
		char *lib;
		int n;

		lib = _pluginLibFromName(plugin, n);
		if (n <= 0)
			return;

		qInfo() << "u_reg" << lib;
		kshark_unregister_plugin(kshark_ctx, lib);
		free(lib);
	};

	auto lamUregUser = [&kshark_ctx](const QString &plugin)
	{
		std::string lib = plugin.toStdString();
		kshark_unregister_plugin(kshark_ctx, lib.c_str());
	};

	for (auto const &p: _ksPluginList)
		lamUregBuiltIn(p);

	for (auto const &p: _userPluginList)
		lamUregUser(p);
}

char *KsPluginManager::_pluginLibFromName(const QString &plugin, int &n)
{
	QString appPath = QCoreApplication::applicationDirPath();
	QString libPath = appPath + "/../lib";
	std::string pluginStr = plugin.toStdString();
	char *lib;

	libPath = QDir::cleanPath(libPath);
	if (!KsUtils::isInstalled() && QDir(libPath).exists()) {
		std::string pathStr = libPath.toStdString();
		n = asprintf(&lib, "%s/plugin-%s.so",
			     pathStr.c_str(), pluginStr.c_str());
	} else {
		n = asprintf(&lib, "%s/plugin-%s.so",
			     KS_PLUGIN_INSTALL_PREFIX, pluginStr.c_str());
	}

	return lib;
}

/**
 * @brief Register a Plugin.
 *
 * @param plugin: Provide here the name of the plugin (as in the CMake-generated
 *		  header file) of a name of the plugin's library file (.so).
 */
void KsPluginManager::registerPlugin(const QString &plugin)
{
	kshark_context *kshark_ctx(nullptr);
	int *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);

	if (plugin.endsWith(".so") && QFileInfo::exists(plugin)) {
		std::string pluginStr = plugin.toStdString();
		struct kshark_plugin_list *pluginPtr =
			kshark_register_plugin(kshark_ctx, pluginStr.c_str());

		_userPluginList.prepend(plugin);

		_registeredUserPlugins[-1].prepend(true);
		for (int i = 0; i < kshark_ctx->n_streams; ++i) {
			_registeredUserPlugins[streamIds[i]].prepend(true);
			kshark_plugin_add_stream(pluginPtr, streamIds[i]);
		}
	} else {
		qCritical() << "ERROR: " << plugin << "cannot be registered!";
	}

	free(streamIds);
}

/** @brief Unregister a Built in KernelShark plugin.
 *<br>
 * WARNING: Do not use this function to unregister User plugins.
 * Instead use directly kshark_unregister_plugin().
 *
 * @param plugin: Provide here the name of the plugin (as in the CMake-generated
 *		  header file) or the name of the plugin's library file (.so).
 *
 */
void KsPluginManager::unregisterPlugin(const QString &plugin)
{
	kshark_context *kshark_ctx(nullptr);
	char *lib;
	int n;

	if (!kshark_instance(&kshark_ctx))
		return;

	auto lamUnreg = [&] (int i) {
		int *streamIds = kshark_all_streams(kshark_ctx);

		kshark_unregister_plugin(kshark_ctx, lib);
		for (int j = 0; j < kshark_ctx->n_streams; ++j)
			_registeredKsPlugins[streamIds[j]][i] = false;

		free(streamIds);
		free(lib);
	};

	for (int i = 0; i < _ksPluginList.count(); ++i) {
		if (_ksPluginList[i] == plugin) {
			/*
			 * The argument is the name of the plugin. From the
			 * name get the library .so file.
			 */
			lib = _pluginLibFromName(plugin, n);
			if (n > 0)
				lamUnreg(i);

			return;

		} else if (plugin.contains("/lib/plugin-" + _ksPluginList[i],
					   Qt::CaseInsensitive)) {
			/*
			 * The argument is the name of the library .so file.
			 */
			n = asprintf(&lib, "%s", plugin.toStdString().c_str());
			if (n > 0)
				lamUnreg(i);

			return;
		}
	}
}

/** @brief Add to the list and initialize user-provided plugins. All other
 *	   previously loaded plugins will be reinitialized and the data will be
 *	   reloaded.
 *
 * @param fileNames: the library files (.so) of the plugins.
*/
void KsPluginManager::addPlugins(const QStringList &fileNames)
{
	kshark_context *kshark_ctx(nullptr);
	int *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i)
		kshark_handle_all_plugins(kshark_ctx, streamIds[i],
					  KSHARK_PLUGIN_CLOSE);

	for (auto const &p: fileNames)
		registerPlugin(p);

	for (int i = 0; i < kshark_ctx->n_streams; ++i)
		kshark_handle_all_plugins(kshark_ctx, streamIds[i],
					  KSHARK_PLUGIN_INIT);

	free(streamIds);
	emit dataReload();
}

/** @brief Update (change) the Plugins for a given Data stream.
 *
 * @param sd: Data stream identifier.
 * @param pluginStates: A vector of plugin's states (0 or 1) telling which
 *			plugins to be loaded.
 */
void KsPluginManager::updatePlugins(int sd, QVector<int> pluginStates)
{
	int nKsPlugins = _registeredKsPlugins[sd].count();
	int nUserPlugins = pluginStates.count() - nKsPlugins;
	kshark_context *kshark_ctx(nullptr);
	kshark_plugin_list* plugins;

	if (!kshark_instance(&kshark_ctx))
		return;

	_registeredUserPlugins[sd] = pluginStates.mid(0, nUserPlugins);
	_registeredKsPlugins[sd] = pluginStates.mid(nUserPlugins, -1);

	plugins = kshark_ctx->plugins;
	for (auto state : pluginStates) {
		if (state)
			kshark_plugin_add_stream(plugins, sd);

		plugins = plugins->next;
	}

	kshark_handle_all_plugins(kshark_ctx, sd, KSHARK_PLUGIN_INIT);
}
