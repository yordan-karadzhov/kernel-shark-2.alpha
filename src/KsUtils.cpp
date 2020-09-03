// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsUtils.cpp
 *  @brief   KernelShark Utils.
 */

// C
#include <dlfcn.h>

// KernelShark
#include "libkshark-plugin.h"
#include "libkshark-tepdata.h"
#include "KsUtils.hpp"
#include "KsPlugins.hpp"
#include "KsWidgetsLib.hpp"

namespace KsUtils {

/** @brief Get a sorted vector of CPU Ids. */
QVector<int> getCPUList(int sd)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;

	if (!kshark_instance(&kshark_ctx))
		return {};

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return {};

	QVector<int> allCPUs = QVector<int>(stream->n_cpus);
	std::iota(allCPUs.begin(), allCPUs.end(), 0);

	return allCPUs;
}

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

QVector<int> getEventIdList(int sd)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	int *ids;

	if (!kshark_instance(&kshark_ctx))
		return {};

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return {};

	ids = kshark_get_all_event_ids(stream);
	QVector<int> allEvts(stream->n_events);
	for (int i = 0; i < stream->n_events; ++i)
		allEvts[i] = ids[i];

	return allEvts;
}

QVector<int> getStreamIdList()
{
	kshark_context *kshark_ctx(nullptr);
	QVector<int> v;
	int *ids;

	if (!kshark_instance(&kshark_ctx))
		return {};

	ids = kshark_all_streams(kshark_ctx);
	v.resize(kshark_ctx->n_streams);
	for (int i = 0; i < kshark_ctx->n_streams; ++i)
		v[i] = ids[i];

	free(ids);
	return v;
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
QStringList getTepEvtName(int sd, int eventId)
{
	QString name(kshark_event_from_id(sd, eventId));

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

	name = kshark_comm_from_pid(sd, pid);
	name += "-";
	name += QString("%1").arg(pid);

	return name;
}

QString streamDescription(kshark_data_stream *stream)
{
	QString descr(stream->file);
	QString buffName(stream->name);
	if (!buffName.isEmpty() && buffName != "top") {
		descr += ":";
		descr += stream->name;
	}

	return descr;
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
	int sd = kshark_open(kshark_ctx, file.toStdString().c_str());
	if (sd < 0) {
		qCritical() << "ERROR:" << sd << "while loading file " << file;
		return sd;
	}

	if (kshark_ctx->stream[sd]->format == KS_TEP_DATA) {
		kshark_tep_init_all_buffers(kshark_ctx, sd);
		for (int i = 0; i < kshark_ctx->n_streams; ++i)
			kshark_tep_handle_plugins(kshark_ctx, i);
	}

	return sd;
}

void KsDataStore::_addPluginsToStream(kshark_context *kshark_ctx, int sd,
				      QVector<kshark_dpi *> plugins)
{
	kshark_data_stream *stream;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	for (auto const &p: plugins) {
		struct kshark_dpi_list *plugin;

		plugin = kshark_register_plugin_to_stream(stream, p, true);
		kshark_handle_dpi(stream, plugin, KSHARK_PLUGIN_INIT);
	}
}

/** Load trace data for file. */
int  KsDataStore::loadDataFile(const QString &file,
			       QVector<kshark_dpi *> plugins)
{
	kshark_context *kshark_ctx(nullptr);
	int sd, n_streams;

	if (!kshark_instance(&kshark_ctx))
		return -EFAULT;

	clear();
	unregisterCPUCollections();
	kshark_close_all(kshark_ctx);

	sd = _openDataFile(kshark_ctx, file);
	if (sd != 0)
		return sd;

	/*
	 * The file may contain multiple buffers so we can have multiple
	 * streams loaded.
	 */
	n_streams = kshark_ctx->n_streams;
	for (sd = 0; sd < n_streams; ++sd)
		_addPluginsToStream(kshark_ctx, sd, plugins);

	_dataSize = kshark_load_all_entries(kshark_ctx, &_rows);
	if (_dataSize <= 0) {
		kshark_close(kshark_ctx, sd);
		return _dataSize;
	}

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
	struct kshark_entry **mergedRows;
	ssize_t nLoaded = _dataSize;
	int i, sd;

	if (!kshark_instance(&kshark_ctx))
		return -EFAULT;

	unregisterCPUCollections();

	sd = _openDataFile(kshark_ctx, file);

	for (i = sd; i < kshark_ctx->n_streams; ++i) {
		kshark_ctx->stream[sd]->calib = kshark_offset_calib;
		kshark_ctx->stream[sd]->calib_array =
			(int64_t *) calloc(1, sizeof(int64_t));
		kshark_ctx->stream[sd]->calib_array[0] = offset;
		kshark_ctx->stream[sd]->calib_array_size = 1;
	}

	_dataSize = kshark_append_all_entries(kshark_ctx, _rows, nLoaded, sd,
					      &mergedRows);

	if (_dataSize <= 0 || _dataSize == nLoaded) {
		QErrorMessage *em = new QErrorMessage();
		em->showMessage(QString("File %1 contains no data.").arg(file));
		em->exec();

		for (i = sd; i < kshark_ctx->n_streams; ++i)
			kshark_close(kshark_ctx, i);

		return _dataSize;
	}

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
	_loadPluginList(KsUtils::getPluginList());
}

QVector<kshark_plugin_list *>
KsPluginManager::_loadPluginList(const QStringList &plugins)
{
	kshark_context *kshark_ctx(nullptr);
	QVector<kshark_plugin_list *> vec;
	kshark_plugin_list *plugin;
	std::string name, lib;
	int nPlugins;

	if (!kshark_instance(&kshark_ctx))
		return vec;

	nPlugins = plugins.count();
	for (int i = 0; i < nPlugins; ++i) {
		if (plugins[i].endsWith(".so")) {
			lib = plugins[i].toStdString();
			name = _pluginNameFromLib(plugins[i]);
		} else {
			lib = _pluginLibFromName(plugins[i]);
			name = plugins[i].toStdString();
		}

		plugin = kshark_find_plugin(kshark_ctx->plugins,
					    lib.c_str());

		if (!plugin) {
			plugin = kshark_register_plugin(kshark_ctx,
							name.c_str(),
							lib.c_str());

			if (plugin)
				vec.append(plugin);
		}
	}

	return vec;
}

QStringList KsPluginManager::getPluginList() const
{
	kshark_context *kshark_ctx(nullptr);
	kshark_plugin_list *plugin;
	QStringList list;

	if (!kshark_instance(&kshark_ctx))
		return {};

	plugin = kshark_ctx->plugins;
	while (plugin) {
		list.append(plugin->file);
		plugin = plugin->next;
	}

	return list;
}

QStringList KsPluginManager::getStreamPluginList(int sd) const
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	kshark_dpi_list *plugin;
	QStringList list;

	if (!kshark_instance(&kshark_ctx))
		return {};

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return {};

	plugin = stream->plugins;
	while (plugin) {
		list.append(plugin->interface->name);
		plugin = plugin->next;
	}

	return list;
}

QVector<int> KsPluginManager::getActivePlugins(int sd) const
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	kshark_dpi_list *plugin;
	QVector<int> vec;
	int i(0);

	if (!kshark_instance(&kshark_ctx))
		return {};

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return {};

	plugin = stream->plugins;

	while (plugin) {
		vec.append(plugin->status & KSHARK_PLUGIN_ENABLED);
		plugin = plugin->next;
		i++;
	}

	return vec;
}

QVector<int> KsPluginManager::getPluginsByStatus(int sd, int status) const
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	kshark_dpi_list *plugin;
	QVector<int> vec;
	int i(0);

	if (!kshark_instance(&kshark_ctx))
		return {};

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return {};

	plugin = stream->plugins;

	while (plugin) {
		if (plugin->status & status)
			vec.append(i);

		plugin = plugin->next;
		i++;
	}

	return vec;
}

void KsPluginManager::registerPluginMenues()
{
	kshark_context *kshark_ctx(nullptr);
	kshark_plugin_list *plugin;

	if (!kshark_instance(&kshark_ctx))
		return;

	for (plugin = kshark_ctx->plugins; plugin; plugin = plugin->next)
		if (plugin->handle && plugin->ctrl_interface) {
			void *dialogPtr = plugin->ctrl_interface(parent());
			if (dialogPtr) {
				QWidget *dialog =
					static_cast<QWidget *>(dialogPtr);
				_pluginDialogs.append(dialog);
			}
		}
}

std::string KsPluginManager::_pluginLibFromName(const QString &plugin)
{
	QString appPath = QCoreApplication::applicationDirPath();
	QString libPath = appPath + "/../lib";
	std::string lib;

	auto lamFileName = [&] () {
		return std::string("/plugin-" + plugin.toStdString() + ".so");
	};

	libPath = QDir::cleanPath(libPath);
	if (!KsUtils::isInstalled() && QDir(libPath).exists())
		lib = libPath.toStdString() + lamFileName();
	else
		lib = std::string(KS_PLUGIN_INSTALL_PREFIX) + lamFileName();

	return lib;
}

std::string KsPluginManager::_pluginNameFromLib(const QString &plugin)
{
	QString name = plugin.section('/', -1);
	name.remove("plugin-");
	name.remove(".so");

	return name.toStdString();
}

/**
 * @brief Register a Plugin.
 *
 * @param plugin: Provide here the name of the plugin (as in the CMake-generated
 *		  header file) or a name of the plugin's library file (.so
 *		  including path).
 */
void KsPluginManager::registerPlugins(const QString &pluginNames)
{
	_userPlugins.append(_loadPluginList(pluginNames.split(' ')));
}

void KsPluginManager::_pluginToStream(const QString &pluginName,
				      QVector<int> streamId,
				      bool reg)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_plugin_list *plugin;
	kshark_data_stream *stream;

	if (!kshark_instance(&kshark_ctx))
		return;

	plugin = kshark_find_plugin_by_name(kshark_ctx->plugins,
					    pluginName.toStdString().c_str());

	if (!plugin || !plugin->process_interface)
		return;

	for (auto const &sd: streamId) {
		stream = kshark_get_data_stream(kshark_ctx, sd);
		if (reg)
			kshark_register_plugin_to_stream(stream,
							 plugin->process_interface,
							 true);
		else
			kshark_unregister_plugin_from_stream(stream,
							     plugin->process_interface);

		kshark_handle_all_dpis(stream, KSHARK_PLUGIN_UPDATE);
	}

	emit dataReload();
}

void KsPluginManager::registerPluginToStream(const QString &pluginName,
					     QVector<int> streamId)
{
	_pluginToStream(pluginName, streamId, true);
}

void KsPluginManager::unregisterPluginFromStream(const QString &pluginName,
						 QVector<int> streamId)
{
	_pluginToStream(pluginName, streamId, false);
}

/**
 * @brief Unregister a list pf plugins.
 *
 * @param pluginNames: Provide here a space separated list of plugin names (as
 *		       in the CMake-generated header file).
 */
void KsPluginManager::unregisterPlugins(const QString &pluginNames)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_plugin_list *plugin;
	kshark_data_stream *stream;
	int *streamArray;

	if (!kshark_instance(&kshark_ctx))
		return;

	for (auto const &name: pluginNames.split(' ')) {
		plugin = kshark_find_plugin_by_name(kshark_ctx->plugins,
						    name.toStdString().c_str());

		streamArray = kshark_all_streams(kshark_ctx);
		for  (int i = 0; i < kshark_ctx->n_streams; ++i) {
			stream = kshark_get_data_stream(kshark_ctx,
							streamArray[i]);
			kshark_unregister_plugin_from_stream(stream,
							     plugin->process_interface);
		}

		kshark_unregister_plugin(kshark_ctx,
					 name.toStdString().c_str(),
					 plugin->file);
	}
}

/** @brief Add to the list and initialize user-provided plugins. All other
 *	   previously loaded plugins will be reinitialized and the data will be
 *	   reloaded.
 *
 * @param fileNames: the library files (.so) of the plugins.
*/
void KsPluginManager::addPlugins(const QStringList &fileNames,
				 QVector<int> streamIds)
{
	QVector<kshark_plugin_list *> plugins;
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;

	if (!kshark_instance(&kshark_ctx))
		return;

	plugins = _loadPluginList(fileNames);
	_userPlugins.append(plugins);

	if (streamIds.isEmpty()) {
		int *streamArray;

		streamIds.resize(kshark_ctx->n_streams);
		streamArray = kshark_all_streams(kshark_ctx);
		for  (int i = 0; i < kshark_ctx->n_streams; ++i)
			streamIds[i] = streamArray[i];

		free(streamArray);
	}

	for (int i = 0; i < streamIds.count(); ++i) {
		stream = kshark_get_data_stream(kshark_ctx, streamIds[i]);

		for (auto const &p: plugins) {
			if (p->process_interface)
				kshark_register_plugin_to_stream(stream,
								 p->process_interface,
								 true);
		}

		kshark_handle_all_dpis(stream, KSHARK_PLUGIN_UPDATE);
	}
}

/** @brief Update (change) the plugins for a given Data stream.
 *
 * @param sd: Data stream identifier.
 * @param pluginStates: A vector of plugin's states (0 or 1) telling which
 *			plugins to be loaded.
 */
void KsPluginManager::updatePlugins(int sd, QVector<int> pluginStates)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	kshark_dpi_list *plugin;
	QVector<int> vec;
	int i(0);

	if (!kshark_instance(&kshark_ctx))
		return;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	plugin = stream->plugins;
	while (plugin) {
		if (pluginStates[i++])
			plugin->status |= KSHARK_PLUGIN_ENABLED;
		else
			plugin->status &= ~KSHARK_PLUGIN_ENABLED;

		plugin = plugin->next;
	}

	kshark_handle_all_dpis(stream, KSHARK_PLUGIN_UPDATE);
}

/**
 * @brief Destroy all Plugin dialogs.
 */
void KsPluginManager::deletePluginDialogs()
{
	/** Delete all register plugin dialogs. */
	for (auto &pd: _pluginDialogs)
		delete pd;
}
