/* -*- mode: c; coding: utf-8 -*- */

#ifndef _BLUEZ_UTILS_H_
#define _BLUEZ_UTILS_H_

#include <glib.h>

#include "btio/btio.h"

GIOChannel*
gatt_connect(const char *src, const char *dst,
	     const char *dst_type, const char *sec_level,
	     int psm, int mtu, BtIOConnect connect_cb,
	     GError **gerr, gpointer user_data);

size_t
gatt_attr_data_from_string(const char *str, uint8_t **data);

#endif // _BLUEZ_UTILS_H_
