/* extcap_gtk.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <gtk/gtk.h>

#include "ui/gtk/gui_utils.h"

#include <extcap_parser.h>
#include "extcap_gtk.h"

GHashTable *extcap_gtk_get_state(GtkWidget *widget) {
	GSList *widget_list, *widget_iter;
	GSList *radio_list = NULL, *radio_iter = NULL;

	GtkWidget *list_widget, *radio_widget, *tree_widget;

	extcap_arg *arg;
	extcap_value *value;
	extcap_complex *parsed_complex;

	GtkTreeSelection *treeselection;
	GtkTreeModel *treemodel;
	GtkTreeIter treeiter;

	GHashTable *ret_hash;

	gchar *call_string = NULL;

	gchar **multi_list = NULL;
	int multi_num = 0;
	gboolean multi_valid, multi_enabled;

	widget_list = (GSList *) g_object_get_data(G_OBJECT(widget),
									EXTCAP_GTK_DATA_KEY_WIDGETLIST);

	if (widget_list == NULL)
		return NULL;

	/* String hash */
	ret_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	for (widget_iter = widget_list; widget_iter; widget_iter = widget_iter->next) {
		list_widget = (GtkWidget *) widget_iter->data;

		if ((arg = (extcap_arg *) g_object_get_data(G_OBJECT(list_widget),
													EXTCAP_GTK_DATA_KEY_ARGPTR)) == NULL) {
			continue;
		}

		switch (arg->arg_type) {
			case EXTCAP_ARG_INTEGER:
			case EXTCAP_ARG_UNSIGNED:
			case EXTCAP_ARG_LONG:
			case EXTCAP_ARG_DOUBLE:
			case EXTCAP_ARG_STRING:
				parsed_complex =
					extcap_parse_complex(arg->arg_type,
										 gtk_entry_get_text(GTK_ENTRY(list_widget)));
				if (parsed_complex == NULL) {
					continue;
				}
				break;
			case EXTCAP_ARG_BOOLEAN:
				parsed_complex =
					extcap_parse_complex(arg->arg_type,
										 gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(list_widget)) ? "true" : "false");
				break;
			case EXTCAP_ARG_MENU:
				break;
			case EXTCAP_ARG_RADIO:
				if ((radio_widget =
					 (GtkWidget *) g_object_get_data(G_OBJECT(list_widget),
													 EXTCAP_GTK_DATA_KEY_FIRSTRADIO)) == NULL) {
					continue;
				}

				if ((radio_list = gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_widget))) == NULL) {
					continue;
				}

				for (radio_iter = radio_list; radio_iter; radio_iter = radio_iter->next) {
					GtkWidget *cur_radio = (GtkWidget *) radio_iter->data;

					if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cur_radio))) {
						if ((value = (extcap_value *) g_object_get_data(G_OBJECT(cur_radio),
																		EXTCAP_GTK_DATA_KEY_VALPTR)) == NULL) {
							continue;
						}

						call_string = g_strdup(value->call);
						break;
					}
				}

				break;
			case EXTCAP_ARG_SELECTOR:
				if ((tree_widget =
					 (GtkWidget *) g_object_get_data(G_OBJECT(list_widget),
													 EXTCAP_GTK_DATA_KEY_TREEVIEW)) == NULL) {
					continue;
				}

				treeselection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_widget));
				treemodel = gtk_tree_view_get_model(GTK_TREE_VIEW(tree_widget));
				if (gtk_tree_selection_get_selected(treeselection, &treemodel, &treeiter)) {
					gtk_tree_model_get(treemodel, &treeiter, EXTCAP_GTK_COL_VALUE, &value, -1);

					call_string = g_strdup(value->call);
				}

				break;
			case EXTCAP_ARG_MULTICHECK:
				if ((tree_widget =
					 (GtkWidget *) g_object_get_data(G_OBJECT(list_widget),
													 EXTCAP_GTK_DATA_KEY_TREEVIEW)) == NULL) {
					continue;
				}

				treeselection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_widget));
				treemodel = gtk_tree_view_get_model(GTK_TREE_VIEW(tree_widget));

				multi_num = 0;

				/* Count the # of items enabled */
				multi_valid = gtk_tree_model_get_iter_first(treemodel, &treeiter);
				while (multi_valid) {
					gtk_tree_model_get(treemodel, &treeiter,
									   EXTCAP_GTK_MULTI_COL_CHECK, &multi_enabled,
									   -1);

					if (multi_enabled)
						multi_num++;

					multi_valid = gtk_tree_model_iter_next(treemodel, &treeiter);
				}

				multi_list = g_new(gchar *, multi_num + 1);

				multi_num = 0;

				/* Count the # of items enabled */
				multi_valid = gtk_tree_model_get_iter_first(treemodel, &treeiter);
				while (multi_valid) {
					gtk_tree_model_get(treemodel, &treeiter,
									   EXTCAP_GTK_MULTI_COL_CHECK, &multi_enabled,
									   EXTCAP_GTK_MULTI_COL_VALUE, &value,
									   -1);

					if (multi_enabled) {
						multi_list[multi_num] = g_strdup(value->call);
						multi_num++;
					}

					multi_valid = gtk_tree_model_iter_next(treemodel, &treeiter);
				}
				multi_list[multi_num] = NULL;

				call_string = g_strjoinv(",", multi_list);

				g_strfreev(multi_list);

				break;
			default:
				break;
		}

		if (parsed_complex == NULL && call_string == NULL)
			continue;

		if (parsed_complex != NULL && call_string == NULL)
			call_string = extcap_get_complex_as_string(parsed_complex);

		g_hash_table_insert(ret_hash, g_strdup(arg->call), g_strdup(call_string));

		g_free(call_string);
		call_string = NULL;

		g_free(parsed_complex);
		parsed_complex = NULL;
	}

	return ret_hash;
}

void extcap_gtk_treeview_vscroll_map_handler(GtkTreeView *treeView, gpointer data) {
	GtkWidget *padBox = (GtkWidget*)data;
	gint x, y;

	g_assert(GTK_IS_BOX(padBox));

	/* Set the padding above the scrollbar to the height of the tree header window */
	gtk_tree_view_convert_bin_window_to_widget_coords(GTK_TREE_VIEW(treeView),
			0, 0, &x, &y);
	gtk_widget_set_size_request(padBox, -1, y);
}

GtkWidget *extcap_gtk_wrap_scroll_treeview(GtkWidget *view) {
	GtkWidget *vscroll, *padbox, *hbox, *vbox;
	GtkAdjustment *padj;

#if GTK_CHECK_VERSION(3, 0, 0)
	padj = gtk_scrollable_get_vadjustment(GTK_SCROLLABLE(view));
#if GTK_CHECK_VERSION(3, 2, 0)
	vscroll = gtk_scrollbar_new(GTK_ORIENTATION_VERTICAL, padj);
#else
	vscroll = gtk_vscrollbar_new(padj);
#endif
#else
	padj = gtk_tree_view_get_vadjustment(GTK_TREE_VIEW(view));
	vscroll = gtk_vscrollbar_new(padj);
#endif

	hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);

	/* First insert the tree view */
	gtk_box_pack_start(GTK_BOX(hbox), view, TRUE, TRUE, 0);
	gtk_widget_show(view);

	/* Pack to the right a vbox containing a box for padding at top and scrollbar */
	vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
	gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);
	gtk_widget_show(vbox);

	padbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
	gtk_box_pack_start(GTK_BOX(vbox), padbox, FALSE, FALSE, 0);
	gtk_widget_show(padbox);

	gtk_box_pack_start(GTK_BOX(vbox), vscroll, TRUE, TRUE, 0);
	gtk_widget_show(vscroll);

	g_object_set_data(G_OBJECT(hbox), EXTCAP_GTK_DATA_KEY_TREEVIEW, view);

	g_signal_connect(view, "map", G_CALLBACK(extcap_gtk_treeview_vscroll_map_handler), padbox);

	return hbox;
}

GtkWidget *extcap_create_gtk_listwidget(extcap_arg *argument, GHashTable *prev_map) {
	GtkCellRenderer *renderer;
	GtkTreeModel *model;
	GtkWidget *view, *retview;
	GtkListStore *store;
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	extcap_value *v = NULL;
	GList * walker = NULL;
	gchar *prev_item = NULL;

	if (g_list_length(argument->values) == 0)
		return NULL;

	view = gtk_tree_view_new();

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));

	store = gtk_list_store_new (EXTCAP_GTK_NUM_COLS, G_TYPE_STRING, G_TYPE_POINTER);

	model = GTK_TREE_MODEL(store);
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

	if (prev_map != NULL)
		prev_item = (gchar *) g_hash_table_lookup(prev_map, argument->call);

	for ( walker = g_list_first(argument->values); walker != NULL; walker = walker->next )
	{
		v = (extcap_value *) walker->data;
		if (  v->display == NULL )
			break;

		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
						   EXTCAP_GTK_COL_DISPLAY, v->display,
						   EXTCAP_GTK_COL_VALUE, v,
						   -1);

		if (prev_item != NULL) {
			if (g_ascii_strcasecmp(prev_item, v->call) == 0) {
				gtk_tree_selection_select_iter(selection, &iter);
			}
		} else if (v->is_default) {
			gtk_tree_selection_select_iter(selection, &iter);
		}
	}

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW (view), -1,
												"Name",  renderer,
												"text", EXTCAP_GTK_COL_DISPLAY, NULL);

	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(view), FALSE);

	retview = extcap_gtk_wrap_scroll_treeview(view);

	if (gtk_tree_model_iter_n_children(model, NULL) > 3)
		gtk_widget_set_size_request(retview, 0, 100);


	/* Tree view has own reference */
	g_object_unref (model);

	return retview;
}

GtkWidget *extcap_create_gtk_radiowidget(extcap_arg *argument, GHashTable *prev_map) {
	GtkWidget *radiobox = NULL, *last_radio = NULL;
	extcap_value *v = NULL;
	GList * walker = NULL;
	gchar *prev_item = NULL;

	if (g_list_length(argument->values) == 0)
		return NULL;

	if (prev_map != NULL)
		prev_item = (gchar *) g_hash_table_lookup(prev_map, argument->call);

	radiobox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);

	for ( walker = g_list_first(argument->values); walker != NULL; walker = walker->next )
	{
		v = (extcap_value *) walker->data;

		if (last_radio == NULL) {
			last_radio = gtk_radio_button_new_with_label(NULL, v->display);
			/* Set a pointer to the first radio button */
			g_object_set_data(G_OBJECT(radiobox), EXTCAP_GTK_DATA_KEY_FIRSTRADIO, last_radio);
		} else {
			last_radio = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(last_radio),
																  v->display);
		}

		/* Set a pointer to the value used in this radio */
		g_object_set_data(G_OBJECT(last_radio), EXTCAP_GTK_DATA_KEY_VALPTR, v);

		if (prev_item != NULL) {
			if (g_ascii_strcasecmp(prev_item, v->call) == 0) {
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(last_radio), TRUE);
			}
		} else if (v->is_default) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(last_radio), TRUE);
		}

		gtk_box_pack_start(GTK_BOX(radiobox), last_radio, TRUE, TRUE, 0);
		gtk_widget_show(last_radio);
	}


	return radiobox;
}

static void extcap_gtk_multicheck_toggled(GtkCellRendererToggle *cell _U_,
										  gchar *path_str,
										  gpointer data) {
	GtkTreeModel *model = (GtkTreeModel *)data;
	GtkTreeIter iter;
	GtkTreePath *path = gtk_tree_path_new_from_string(path_str);
	gboolean enabled;

	gtk_tree_model_get_iter(model, &iter, path);
	gtk_tree_model_get(model, &iter, EXTCAP_GTK_MULTI_COL_CHECK, &enabled, -1);

	enabled ^= 1;

	gtk_list_store_set(GTK_LIST_STORE (model), &iter, EXTCAP_GTK_MULTI_COL_CHECK, enabled, -1);

	gtk_tree_path_free (path);
}

GtkWidget *extcap_create_gtk_rangewidget(extcap_arg *argument, GHashTable *prev_map _U_)
{
	GtkWidget *spinButton;
	GtkAdjustment *adjustment;

	gfloat def = 0.0, min = 0.0, max = 0.0;

	switch (argument->arg_type)
	{
	case EXTCAP_ARG_INTEGER:
		def = (gfloat) extcap_complex_get_int(argument->default_complex);
		min = (gfloat) extcap_complex_get_int(argument->range_start);
		max = (gfloat) extcap_complex_get_int(argument->range_end);
		break;
	case EXTCAP_ARG_UNSIGNED:
		def = (gfloat) extcap_complex_get_uint(argument->default_complex);
		min = (gfloat) extcap_complex_get_uint(argument->range_start);
		max = (gfloat) extcap_complex_get_uint(argument->range_end);
		break;
	case EXTCAP_ARG_LONG:
		def = (gfloat) extcap_complex_get_long(argument->default_complex);
		min = (gfloat) extcap_complex_get_long(argument->range_start);
		max = (gfloat) extcap_complex_get_long(argument->range_end);
		break;
	case EXTCAP_ARG_DOUBLE:
		def = (gfloat) extcap_complex_get_double(argument->default_complex);
		min = (gfloat) extcap_complex_get_double(argument->range_start);
		max = (gfloat) extcap_complex_get_double(argument->range_end);
		break;
	default:
		return NULL;
		break;
	}

	adjustment = gtk_adjustment_new(def, min, max, 1.0, 10.0, 0.0);

	spinButton = gtk_spin_button_new(adjustment, 0, 0);
	gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (spinButton), TRUE);
	gtk_widget_set_size_request(spinButton, 80, -1);

	return spinButton;
}

GtkWidget *extcap_create_gtk_multicheckwidget(extcap_arg *argument, GHashTable *prev_map) {
	GtkCellRenderer *renderer, *togglerenderer;
	GtkTreeModel *model;
	GtkWidget *view, *retview;
	GtkListStore *store;
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	extcap_value *v = NULL;
	GList * walker = NULL;
	gchar *prev_item = NULL;
	gchar **prev_list = NULL, **prev_iter = NULL;
	gboolean prev_value, prev_matched;

	if (g_list_length(argument->values) == 0)
		return NULL;

	view = gtk_tree_view_new();

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));

	store = gtk_list_store_new (EXTCAP_GTK_MULTI_NUM_COLS, G_TYPE_BOOLEAN, G_TYPE_STRING, G_TYPE_POINTER);

	model = GTK_TREE_MODEL(store);
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_NONE);

	if (prev_map != NULL)
		prev_item = (gchar *) g_hash_table_lookup(prev_map, argument->call);

	if (prev_item != NULL)
		prev_list = g_strsplit(prev_item, ",", 0);

	for ( walker = g_list_first(argument->values); walker != NULL; walker = walker->next )
	{
		v = (extcap_value *) walker->data;
		if (  v->display == NULL )
			break;

		prev_value = FALSE;
		prev_matched = FALSE;
		gtk_list_store_append(store, &iter);

		if (prev_list != NULL) {
			prev_matched = FALSE;
			prev_iter = prev_list;

			while (*prev_iter != NULL) {
				if (g_strcmp0(*prev_iter, v->call) == 0) {
					prev_matched = TRUE;
					prev_value = TRUE;
					break;
				}

				prev_iter++;
			}
		}

		if (prev_matched == FALSE)
			prev_value = v->enabled;

		gtk_list_store_set(store, &iter,
						   EXTCAP_GTK_MULTI_COL_CHECK, prev_value,
						   EXTCAP_GTK_MULTI_COL_DISPLAY, v->display,
						   EXTCAP_GTK_MULTI_COL_VALUE, v,
						   -1);
	}

	if (prev_list != NULL)
		g_strfreev(prev_list);

	renderer = gtk_cell_renderer_text_new();
	togglerenderer = gtk_cell_renderer_toggle_new();
	g_signal_connect(togglerenderer, "toggled", G_CALLBACK(extcap_gtk_multicheck_toggled), model);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1,
												"Enabled", togglerenderer, "active", EXTCAP_GTK_MULTI_COL_CHECK,
												NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1,
												"Name",  renderer, "text", EXTCAP_GTK_MULTI_COL_DISPLAY,
												NULL);

	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(view), FALSE);

	retview = extcap_gtk_wrap_scroll_treeview(view);

	if (gtk_tree_model_iter_n_children(model, NULL) > 3)
		gtk_widget_set_size_request(retview, 0, 100);

	/* Tree view has own reference */
	g_object_unref (model);


	return retview;
}


void extcap_gtk_free_args(GtkWidget *vbox) {
	GList *arguments =
		(GList *) g_object_get_data(G_OBJECT(vbox), EXTCAP_GTK_DATA_KEY_ARGPTR);
	extcap_free_arg_list(arguments);
	g_object_set_data(G_OBJECT(vbox), EXTCAP_GTK_DATA_KEY_ARGPTR, NULL);
}

GSList *extcap_populate_gtk_vbox(GList *arguments, GtkWidget *vbox,
								 GHashTable *prev_map) {
	GSList *widget_toplist = NULL;

	extcap_arg *arg_iter = NULL;

	extcap_complex *prev_complex = NULL;
	gchar *prev_call, *default_str;

	GList * arg_list = g_list_first(arguments);
	arg_iter = (extcap_arg*)(arg_list->data);

	g_object_set_data(G_OBJECT(vbox), EXTCAP_GTK_DATA_KEY_ARGPTR, arguments);

	while (arg_list != NULL) {
		GtkWidget *hbox = NULL, *label = NULL, *item = NULL;

		arg_iter = (extcap_arg*)(arg_list->data);

		/* A new storage box for label + element */

		hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5, FALSE);

		if (prev_map != NULL &&
			(prev_call = (gchar *) g_hash_table_lookup(prev_map, arg_iter->call)) != NULL) {
			prev_complex = extcap_parse_complex(arg_iter->arg_type, prev_call);
		} else {
			prev_complex = NULL;
		}

		switch (arg_iter->arg_type) {
			case EXTCAP_ARG_INTEGER:
			case EXTCAP_ARG_UNSIGNED:
			case EXTCAP_ARG_LONG:
			case EXTCAP_ARG_DOUBLE:
				label = gtk_label_new(arg_iter->display);
				gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.1f);
				item = extcap_create_gtk_rangewidget(arg_iter, prev_map);
				if ( item == NULL )
				{
					item = gtk_entry_new();

					if (prev_complex != NULL) {
						default_str = extcap_get_complex_as_string(prev_complex);
						gtk_entry_set_text(GTK_ENTRY(item), default_str);
						g_free(default_str);
					} else if (arg_iter->default_complex != NULL) {
						default_str = extcap_get_complex_as_string(arg_iter->default_complex);
						gtk_entry_set_text(GTK_ENTRY(item), default_str);
						g_free(default_str);
					}
				}
				break;
			case EXTCAP_ARG_STRING:
				label = gtk_label_new(arg_iter->display);

				item = gtk_entry_new();

				if (prev_complex != NULL) {
					default_str = extcap_get_complex_as_string(prev_complex);
					gtk_entry_set_text(GTK_ENTRY(item), default_str);
					g_free(default_str);
				} else if (arg_iter->default_complex != NULL) {
					default_str = extcap_get_complex_as_string(arg_iter->default_complex);
					gtk_entry_set_text(GTK_ENTRY(item), default_str);
					g_free(default_str);
				}

				break;
			case EXTCAP_ARG_BOOLEAN:
				item = gtk_check_button_new_with_label(arg_iter->display);

				if (prev_complex != NULL) {
					if (extcap_complex_get_bool(prev_complex))
						gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(item), TRUE);
				} else if (arg_iter->default_complex != NULL &&
					extcap_complex_get_bool(arg_iter->default_complex)) {
					gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(item), TRUE);
				}

				break;
			case EXTCAP_ARG_MENU:
				break;
			case EXTCAP_ARG_RADIO:
				label = gtk_label_new(arg_iter->display);
				gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.1f);
				item = extcap_create_gtk_radiowidget(arg_iter, prev_map);
				break;
			case EXTCAP_ARG_SELECTOR:
				label = gtk_label_new(arg_iter->display);
				gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.1f);
				item = extcap_create_gtk_listwidget(arg_iter, prev_map);
				break;
			case EXTCAP_ARG_MULTICHECK:
				label = gtk_label_new(arg_iter->display);
				gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.1f);
				item = extcap_create_gtk_multicheckwidget(arg_iter, prev_map);
				break;
			default:
				break;
		}

		if (prev_complex != NULL)
			extcap_free_complex(prev_complex);

		if (label != NULL) {
			gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 5);
			gtk_widget_show(label);
		}

		if (item != NULL) {
			gtk_box_pack_start(GTK_BOX(hbox), item, TRUE, TRUE, 0);
			gtk_widget_show(item);
			g_object_set_data(G_OBJECT(item), EXTCAP_GTK_DATA_KEY_ARGPTR, arg_iter);

			if (arg_iter->tooltip != NULL) {
				gtk_widget_set_tooltip_text(item, arg_iter->tooltip);
			}

			widget_toplist = g_slist_append(widget_toplist, item);
		}

		gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 1);

		gtk_widget_show(hbox);

		arg_list = arg_list->next;
	}

	return widget_toplist;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
