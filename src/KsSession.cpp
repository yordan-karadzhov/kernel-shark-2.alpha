// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsSession.cpp
 *  @brief   KernelShark Session.
 */

// KernelShark
#include "libkshark.h"
#include "libkshark-tepdata.h"
#include "KsSession.hpp"
#include "KsMainWindow.hpp"

/** Create a KsSession object. */
KsSession::KsSession()
{
	_config = kshark_config_new("kshark.config.session",
				    KS_CONFIG_JSON);
}

/** Destroy a KsSession object. */
KsSession::~KsSession()
{
	kshark_free_config_doc(_config);
}

/** Import a user session from a Json file. */
bool KsSession::importFromFile(QString jfileName)
{
	kshark_config_doc *configTmp =
		kshark_open_config_file(jfileName.toStdString().c_str(),
					"kshark.config.session");

	if (configTmp) {
		kshark_free_config_doc(_config);
		_config = configTmp;
		return true;
	}

	return false;
}

/** Export the current user session from a Json file. */
void KsSession::exportToFile(QString jfileName)
{
	kshark_save_config_file(jfileName.toStdString().c_str(), _config);
}

/**
 * @brief Save the state of the visualization model.
 *
 * @param histo: Input location for the model descriptor.
 */
void KsSession::saveVisModel(kshark_trace_histo *histo)
{
	kshark_config_doc *model =
		kshark_export_model(histo, KS_CONFIG_JSON);

	kshark_config_doc_add(_config, "Model", model);
}

/**
 * @brief Load the state of the visualization model.
 *
 * @param model: Input location for the KsGraphModel object.
 */
void KsSession::loadVisModel(KsGraphModel *model)
{
	kshark_config_doc *modelConf = kshark_config_alloc(KS_CONFIG_JSON);

	if (!kshark_config_doc_get(_config, "Model", modelConf))
		return;

	kshark_import_model(model->histo(), modelConf);
	model->update();
}

/** Save the trace data file. */
void KsSession::saveDataFile(QString fileName)
{
	kshark_config_doc *file =
		kshark_export_trace_file(fileName.toStdString().c_str(),
					 KS_CONFIG_JSON);

	kshark_config_doc_add(_config, "Data", file);
}

/** Get the trace data file. */
QString KsSession::getDataFile(kshark_context *kshark_ctx)
{
	kshark_config_doc *file = kshark_config_alloc(KS_CONFIG_JSON);
	int sd;

	if (!kshark_config_doc_get(_config, "Data", file))
		return QString();

	sd = kshark_import_trace_file(kshark_ctx, file);
	if (sd)
		return QString(kshark_ctx->stream[sd]->file);

	return QString();
}

/**
 * @brief Save the configuration of the filters to file.
 *
 * @param kshark_ctx: Input location for context pointer.
 */
void KsSession::saveFilters(kshark_context *kshark_ctx,
			    const QString &fileName)
{
	kshark_config_doc *conf(nullptr);

	kshark_export_all_dstreams(kshark_ctx, &conf);
	kshark_save_config_file(fileName.toStdString().c_str(), conf);
	kshark_free_config_doc(conf);
}

/**
 * @brief Load the configuration of the filters and filter the data.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param data: Input location for KsDataStore object;
 */
void KsSession::loadFilters(kshark_context *kshark_ctx,
			    const QString &fileName,
			    KsDataStore *data)
{
	json_object *jconf, *jall_stream, *jstream, *jdata, *jfile, *jfilters;
	kshark_config_doc *conf =
		kshark_open_config_file(fileName.toStdString().c_str(),
				        "kshark.config.filter");
	int n, sd, *streamIds = kshark_all_streams(kshark_ctx);
	bool doReload(false);

	if (!conf)
		return;

	if (conf->format != KS_CONFIG_JSON)
		return;

	jconf = KS_JSON_CAST(conf->conf_doc);

	if (!json_object_object_get_ex(jconf, "data streams", &jall_stream))
		return;

	if (json_object_get_type(jall_stream) != json_type_array)
		return;

	n = json_object_array_length(jall_stream);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		for (int j = 0; j < n; ++j) {
			char abs_path[FILENAME_MAX];
			const char *file;

			jstream = json_object_array_get_idx(jall_stream, j);
			json_object_object_get_ex(jstream, "data", &jdata);
			json_object_object_get_ex(jdata, "file", &jfile);
			file = json_object_get_string(jfile);

			if (!realpath(kshark_ctx->stream[sd]->file, abs_path))
				continue;

			if (strcmp(file, abs_path) == 0) {
				json_object_object_get_ex(jstream,
							  "filters",
							  &jfilters);

				kshark_config_doc *filters =
					kshark_json_to_conf(jfilters);

				kshark_import_all_filters(kshark_ctx,
							  sd, filters);
				kshark_free_config_doc(filters);
			}
		}

		if (kshark_ctx->stream[sd]->format == KS_TEP_DATA &&
		    kshark_tep_filter_is_set(kshark_ctx->stream[sd]))
			doReload = true;
	}

	free(streamIds);

	if (doReload)
		data->reload();
	else
		data->update();

	emit data->updateWidgets(data);
}

/**
 * @brief Save the configuration information for all load Data streams.
 *
 * @param kshark_ctx: Input location for context pointer.
 */
void KsSession::saveDataStreams(kshark_context *kshark_ctx)
{
	kshark_export_all_dstreams(kshark_ctx, &_config);
}

/**
 * @brief Load Data streams.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param data:  Input location for KsDataStore object;
 * @param plugins: Input location for KsPluginManager object;
 */
void KsSession::loadDataStreams(kshark_context *kshark_ctx,
				KsDataStore *data,
				KsPluginManager *plugins)
{
	ssize_t dataSize;
	int *streamIds;

	data->unregisterCPUCollections();

	dataSize = kshark_import_all_dstreams(kshark_ctx,
					      _config,
					      data->rows_r());
	if (dataSize < 0) {
		data->clear();
		return;
	}

	data->setSize(dataSize);

	data->registerCPUCollections();
	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i)
		plugins->addStream(streamIds[i]);

	free(streamIds);
}

/**
 * @brief Save the state of the table.
 *
 * @param view: Input location for the KsTraceViewer widget.
 */
void KsSession::saveTable(const KsTraceViewer &view) {
	kshark_config_doc *topRow = kshark_config_alloc(KS_CONFIG_JSON);
	int64_t r = view.getTopRow();

	topRow->conf_doc = json_object_new_int64(r);
	kshark_config_doc_add(_config, "ViewTop", topRow);
}

/**
 * @brief Load the state of the table.
 *
 * @param view: Input location for the KsTraceViewer widget.
 */
void KsSession::loadTable(KsTraceViewer *view) {
	kshark_config_doc *topRow = kshark_config_alloc(KS_CONFIG_JSON);
	size_t r = 0;

	if (!kshark_config_doc_get(_config, "ViewTop", topRow))
		return;

	if (_config->format == KS_CONFIG_JSON)
		r = json_object_get_int64(KS_JSON_CAST(topRow->conf_doc));

	view->setTopRow(r);
}

/**
 * @brief Save the KernelShark Main window size.
 *
 * @param window: Input location for the KsMainWindow widget.
 */
void KsSession::saveMainWindowSize(const QMainWindow &window)
{
	kshark_config_doc *windowConf = kshark_config_alloc(KS_CONFIG_JSON);
	int width = window.width(), height = window.height();
	json_object *jwindow;

	if (window.isFullScreen()) {
		jwindow = json_object_new_string("FullScreen");
	} else {
		jwindow = json_object_new_array();
		json_object_array_put_idx(jwindow, 0, json_object_new_int(width));
		json_object_array_put_idx(jwindow, 1, json_object_new_int(height));
	}

	windowConf->conf_doc = jwindow;
	kshark_config_doc_add(_config, "MainWindow", windowConf);
}

/**
 * @brief Load the KernelShark Main window size.
 *
 * @param window: Input location for the KsMainWindow widget.
 */
void KsSession::loadMainWindowSize(KsMainWindow *window)
{
	kshark_config_doc *windowConf = kshark_config_alloc(KS_CONFIG_JSON);
	json_object *jwindow, *jwidth, *jheight;
	int width, height;

	if (!kshark_config_doc_get(_config, "MainWindow", windowConf))
		return;

	if (_config->format == KS_CONFIG_JSON) {
		jwindow = KS_JSON_CAST(windowConf->conf_doc);
		if (json_object_get_type(jwindow) == json_type_string &&
		    QString(json_object_get_string(jwindow)) == "FullScreen") {
			window->setFullScreenMode(true);
			return;
		}

		jwidth = json_object_array_get_idx(jwindow, 0);
		jheight = json_object_array_get_idx(jwindow, 1);

		width = json_object_get_int(jwidth);
		height = json_object_get_int(jheight);

		window->setFullScreenMode(false);
		window->resize(width, height);
	}
}

/**
 * @brief Save the state of the Main window spliter.
 *
 * @param splitter: Input location for the splitter widget.
 */
void KsSession::saveSplitterSize(const QSplitter &splitter)
{
	kshark_config_doc *spl = kshark_config_alloc(KS_CONFIG_JSON);
	json_object *jspl = json_object_new_array();
	QList<int> sizes = splitter.sizes();

	json_object_array_put_idx(jspl, 0, json_object_new_int(sizes[0]));
	json_object_array_put_idx(jspl, 1, json_object_new_int(sizes[1]));

	spl->conf_doc = jspl;
	kshark_config_doc_add(_config, "Splitter", spl);
}

/**
 * @brief Load the state of the Main window spliter.
 *
 * @param splitter: Input location for the splitter widget.
 */
void KsSession::loadSplitterSize(QSplitter *splitter)
{
	kshark_config_doc *spl = kshark_config_alloc(KS_CONFIG_JSON);
	json_object *jspl, *jgraphsize, *jviewsize;
	int graphSize(1), viewSize(1);
	QList<int> sizes;

	if (!kshark_config_doc_get(_config, "Splitter", spl))
		return;

	if (_config->format == KS_CONFIG_JSON) {
		jspl = KS_JSON_CAST(spl->conf_doc);
		jgraphsize = json_object_array_get_idx(jspl, 0);
		jviewsize = json_object_array_get_idx(jspl, 1);

		graphSize = json_object_get_int(jgraphsize);
		viewSize = json_object_get_int(jviewsize);

		if (graphSize == 0 && viewSize == 0) {
			/* 0/0 spliter ratio is undefined. Make it 1/1. */
			viewSize = graphSize = 1;
		}
	}

	sizes << graphSize << viewSize;
	splitter->setSizes(sizes);
}

/** @brief Save the Color scheme used. */
void KsSession::saveColorScheme() {
	kshark_config_doc *colSch = kshark_config_alloc(KS_CONFIG_JSON);
	double s = KsPlot::Color::getRainbowFrequency();

	colSch->conf_doc = json_object_new_double(s);
	kshark_config_doc_add(_config, "ColorScheme", colSch);
}

/** @brief Get the Color scheme used. */
float KsSession::getColorScheme() {
	kshark_config_doc *colSch = kshark_config_alloc(KS_CONFIG_JSON);

	/* Default color scheme. */
	float s = 0.75;

	if (!kshark_config_doc_get(_config, "ColorScheme", colSch))
		return s;

	if (_config->format == KS_CONFIG_JSON)
		s = json_object_get_double(KS_JSON_CAST(colSch->conf_doc));

	return s;
}

/**
 * @brief Save the list of the graphs plotted.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param graphs: Input location for the KsTraceGraph widget..
 */
void KsSession::saveGraphs(kshark_context *kshark_ctx,
			   KsTraceGraph &graphs)
{
	int *streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		_saveCPUPlots(streamIds[i], graphs.glPtr());
		_saveTaskPlots(streamIds[i], graphs.glPtr());
	}

	free(streamIds);
	_saveComboPlots(graphs.glPtr());
}

/**
 * @brief Load the list of the graphs and plot.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param graphs: Input location for the KsTraceGraph widget.
 */
void KsSession::loadGraphs(kshark_context *kshark_ctx,
			   KsTraceGraph &graphs)
{
	int sd, *streamIds = kshark_all_streams(kshark_ctx);

	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		graphs.cpuReDraw(sd, _getCPUPlots(sd));
		graphs.taskReDraw(sd, _getTaskPlots(sd));
	}

	free(streamIds);
	QVector<QVector<int>> combos = _getComboPlots();
	for (auto const &cp: combos) {
		graphs.comboReDraw(0, cp);
	}
}

void KsSession::_savePlots(int sd, KsGLWidget *glw, bool cpu)
{
	kshark_config_doc *streamsConf = kshark_config_alloc(KS_CONFIG_JSON);
	json_object *jallStreams, *jstream, *jstreamId, *jplots;
	QVector<int> plotIds;
	int nStreams;

	if (cpu) {
		plotIds = glw->_streamPlots[sd]._cpuList;
	} else {
		plotIds = glw->_streamPlots[sd]._taskList;
	}

	if (!kshark_config_doc_get(_config, "data streams", streamsConf) ||
	    streamsConf->format != KS_CONFIG_JSON)
		return;

	jallStreams = KS_JSON_CAST(streamsConf->conf_doc);
	if (json_object_get_type(jallStreams) != json_type_array)
		return;

	nStreams = json_object_array_length(jallStreams);
	for (int i = 0; i < nStreams; ++i) {
		jstream = json_object_array_get_idx(jallStreams, i);
		if (json_object_object_get_ex(jstream, "stream id", &jstreamId) &&
		    json_object_get_int(jstreamId) == sd)
			break;

		jstream = nullptr;
	}

	if (!jstream)
		return;

	jplots = json_object_new_array();
	for (int i = 0; i < plotIds.count(); ++i) {
		json_object *jcpu = json_object_new_int(plotIds[i]);
		json_object_array_put_idx(jplots, i, jcpu);
	}

	if (cpu)
		json_object_object_add(jstream, "CPUPlots", jplots);
	else
		json_object_object_add(jstream, "TaskPlots", jplots);
}

void KsSession::_saveCPUPlots(int sd, KsGLWidget *glw)
{
	_savePlots(sd, glw, true);
}

void KsSession::_saveTaskPlots(int sd, KsGLWidget *glw)
{
	_savePlots(sd, glw, false);
}

void KsSession::_saveComboPlots(KsGLWidget *glw)
{
	kshark_config_doc *combos = kshark_config_alloc(KS_CONFIG_JSON);
	int var, nCombos = glw->_comboPlots.count();
	json_object *jcombo, *jplots;

	jplots = json_object_new_array();
	for (int i = 0; i < nCombos; ++i) {
		jcombo = json_object_new_array();

		var = glw->_comboPlots[i]._hostStreamId;
		json_object_array_put_idx(jcombo, 0, json_object_new_int(var));

		var = glw->_comboPlots[i]._hostPid;
		json_object_array_put_idx(jcombo, 1, json_object_new_int(var));

		var = glw->_comboPlots[i]._guestStreamId;
		json_object_array_put_idx(jcombo, 2, json_object_new_int(var));

		var = glw->_comboPlots[i]._vcpu;
		json_object_array_put_idx(jcombo, 3, json_object_new_int(var));

		json_object_array_put_idx(jplots, i, jcombo);
	}

	combos->conf_doc = jplots;
	kshark_config_doc_add(_config, "ComboPlots", combos);
}

QVector<int> KsSession::_getPlots(int sd, bool cpu)
{
	kshark_config_doc *streamsConf = kshark_config_alloc(KS_CONFIG_JSON);
	json_object *jallStreams, *jstream, *jstreamId, *jplots;
	int nStreams, nPlots, id;
	const char *plotKey;
	QVector<int> plots;

	if (!kshark_config_doc_get(_config, "data streams", streamsConf) ||
	    streamsConf->format != KS_CONFIG_JSON)
		return plots;

	jallStreams = KS_JSON_CAST(streamsConf->conf_doc);
	if (json_object_get_type(jallStreams) != json_type_array)
		return plots;

	nStreams = json_object_array_length(jallStreams);
	for (int i = 0; i < nStreams; ++i) {
		jstream = json_object_array_get_idx(jallStreams, i);
		if (json_object_object_get_ex(jstream, "stream id", &jstreamId) &&
		    json_object_get_int(jstreamId) == sd)
			break;

		jstream = nullptr;
	}

	if (!jstream)
		return plots;

	if (cpu)
		plotKey = "CPUPlots";
	else
		plotKey = "TaskPlots";

	if (!json_object_object_get_ex(jstream, plotKey, &jplots) ||
	    json_object_get_type(jplots) != json_type_array)
		return plots;

	nPlots = json_object_array_length(jplots);
	for (int i = 0; i < nPlots; ++i) {
		id = json_object_get_int(json_object_array_get_idx(jplots, i));
		plots.append(id);
	}

	return plots;
}

QVector<int> KsSession::_getCPUPlots(int sd)
{
	return _getPlots(sd, true);
}

QVector<int> KsSession::_getTaskPlots(int sd)
{
	return _getPlots(sd, false);
}

QVector<QVector<int>> KsSession::_getComboPlots()
{
	kshark_config_doc *combos = kshark_config_alloc(KS_CONFIG_JSON);
	int nPlots, sdHost, sdGuest, pidHost, vcpu;
	json_object *jplots, *jcombo;
	QVector<QVector<int>> vec;

	if (!kshark_config_doc_get(_config, "ComboPlots", combos))
		return vec;

	if (_config->format == KS_CONFIG_JSON) {
		jplots = KS_JSON_CAST(combos->conf_doc);
		if (json_object_get_type(jplots) != json_type_array)
			return vec;

		nPlots = json_object_array_length(jplots);
		for (int i = 0; i < nPlots; ++i) {
			jcombo = json_object_array_get_idx(jplots, i);
			if (json_object_get_type(jcombo) != json_type_array)
				return vec;

			sdHost = json_object_get_int(json_object_array_get_idx(jcombo, 0));
			pidHost = json_object_get_int(json_object_array_get_idx(jcombo, 1));
			sdGuest = json_object_get_int(json_object_array_get_idx(jcombo, 2));
			vcpu = json_object_get_int(json_object_array_get_idx(jcombo, 3));

			vec.append({sdHost, pidHost, sdGuest, vcpu});
		}
	}

	return vec;
}

/**
 * @brief Save the state of the Dual marker.
 *
 * @param dm: Input location for the KsDualMarkerSM object.
 */
void KsSession::saveDualMarker(KsDualMarkerSM *dm)
{
	kshark_config_doc *markers =
		kshark_config_new("kshark.config.markers", KS_CONFIG_JSON);
	json_object *jd_mark = KS_JSON_CAST(markers->conf_doc);

	auto save_mark = [&jd_mark] (KsGraphMark *m, const char *name)
	{
		json_object *jmark = json_object_new_object();

		if (m->_isSet) {
			json_object_object_add(jmark, "isSet",
					       json_object_new_boolean(true));

			json_object_object_add(jmark, "row",
					       json_object_new_int(m->_pos));
		} else {
			json_object_object_add(jmark, "isSet",
					       json_object_new_boolean(false));
		}

		json_object_object_add(jd_mark, name, jmark);
	};

	save_mark(&dm->markerA(), "markA");
	save_mark(&dm->markerB(), "markB");

	if (dm->getState() == DualMarkerState::A)
		json_object_object_add(jd_mark, "Active",
				       json_object_new_string("A"));
	else
		json_object_object_add(jd_mark, "Active",
				       json_object_new_string("B"));

	kshark_config_doc_add(_config, "Markers", markers);
}

/**
 * @brief Load the state of the Dual marker.
 *
 * @param dm: Input location for the KsDualMarkerSM object.
 * @param graphs: Input location for the KsTraceGraph widget.
 */
void KsSession::loadDualMarker(KsDualMarkerSM *dm, KsTraceGraph *graphs)
{
	uint64_t pos;

	dm->reset();
	dm->setState(DualMarkerState::A);
	if (_getMarker("markA", &pos)) {
		graphs->markEntry(pos);
	} else {
		dm->markerA().remove();
	}

	dm->setState(DualMarkerState::B);
	if (_getMarker("markB", &pos)) {
		graphs->markEntry(pos);
	} else {
		dm->markerB().remove();
	}

	dm->setState(_getMarkerState());
	if (dm->activeMarker()._isSet) {
		pos = dm->activeMarker()._pos;
		emit graphs->glPtr()->updateView(pos, true);
	}
}

json_object *KsSession::_getMarkerJson()
{
	kshark_config_doc *markers =
		kshark_config_alloc(KS_CONFIG_JSON);

	if (!kshark_config_doc_get(_config, "Markers", markers) ||
	    !kshark_type_check(markers, "kshark.config.markers"))
		return nullptr;

	return KS_JSON_CAST(markers->conf_doc);
}

bool KsSession::_getMarker(const char* name, size_t *pos)
{
	json_object *jd_mark, *jmark;

	*pos = 0;
	jd_mark = _getMarkerJson();
	if (!jd_mark)
		return false;

	if (json_object_object_get_ex(jd_mark, name, &jmark)) {
		json_object *jis_set;
		json_object_object_get_ex(jmark, "isSet", &jis_set);
		if (!json_object_get_boolean(jis_set))
			return false;

		json_object *jpos;
		json_object_object_get_ex(jmark, "row", &jpos);
		*pos = json_object_get_int64(jpos);
	}

	return true;
}

DualMarkerState KsSession::_getMarkerState()
{
	json_object *jd_mark, *jstate;
	const char* state;

	jd_mark = _getMarkerJson();
	json_object_object_get_ex(jd_mark, "Active", &jstate);
	state = json_object_get_string(jstate);

	if (strcmp(state, "A") == 0)
		return DualMarkerState::A;

	return DualMarkerState::B;
}

/**
 * @brief Save the configuration of the plugins.
 *
 * @param pm: Input location for the KsPluginManager object.
 */
void KsSession::savePlugins(const KsPluginManager &pm)
{
	kshark_config_doc *plugins =
		kshark_config_new("kshark.config.plugins", KS_CONFIG_JSON);
	json_object *jplugins = KS_JSON_CAST(plugins->conf_doc);
	const KsPluginMap &registeredPlugins = pm._registeredKsPlugins;
	const QStringList &pluginList = pm._ksPluginList;
	json_object *jpl, *jmap, *jstream, *jlist;

	jpl = json_object_new_array();
	for (auto &p: pluginList) {
		std::string name = p.toStdString();
		json_object_array_add(jpl, json_object_new_string(name.c_str()));
	}
	json_object_object_add(jplugins, "Plugin List", jpl);

	jmap = json_object_new_array();
	for (auto &s: registeredPlugins.keys()) {
		jstream = json_object_new_object();
		if (s < 0)
			json_object_object_add(jstream, "stream",
					       json_object_new_string("default"));
		else
			json_object_object_add(jstream, "stream",
					       json_object_new_int(s));

		jlist = json_object_new_array();
		for (auto &p: registeredPlugins[s])
			json_object_array_add(jlist, json_object_new_int(p));
		json_object_object_add(jstream, "registered", jlist);

		json_object_array_add(jmap, jstream);
	}
	json_object_object_add(jplugins, "Stream map", jmap);

	kshark_config_doc_add(_config, "Plugins", plugins);
}

/**
 * @brief Load the configuration of the plugins.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param pm: Input location for the KsPluginManager object.
 */
void KsSession::loadPlugins(kshark_context *kshark_ctx, KsPluginManager *pm)
{
// 	kshark_config_doc *plugins = kshark_config_alloc(KS_CONFIG_JSON);
// 	json_object *jplugins, *jlist, *jpl;
// 	const char *pluginName;
// 	QVector<int> pluginIds;
// 	int length, index;
// 	bool loaded;
// 
// 	if (!kshark_config_doc_get(_config, "Plugins", plugins) ||
// 	    !kshark_type_check(plugins, "kshark.config.plugins"))
// 		return;
// 
// 	if (plugins->format == KS_CONFIG_JSON) {
// 		jplugins = KS_JSON_CAST(plugins->conf_doc);
// 		json_object_object_get_ex(jplugins, "Plugin List", &jlist);
// 		if (!jlist ||
// 	            json_object_get_type(jlist) != json_type_array ||
// 		    !json_object_array_length(jlist))
// 			return;
// 
// 		length = json_object_array_length(jlist);
// 		for (int i = 0; i < length; ++i) {
// 			jpl = json_object_array_get_idx(jlist, i);
// 			pluginName = json_object_get_string(json_object_array_get_idx(jpl, 0));
// 			index = pm->_ksPluginList.indexOf(pluginName);
// 			loaded = json_object_get_boolean(json_object_array_get_idx(jpl, 1));
// 			if (index >= 0 && loaded)
// 				pluginIds.append(index);
// 		}
// 	}
// 
// 	pm->updatePlugins(pluginIds);
}
