// -*- mode: c++; coding: utf-8; tab-width: 4 -*-

// Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
// This software is under the terms of Apache License v2 or later.

#ifndef _MIBAND_DEBUG_H_
#define _MIBAND_DEBUG_H_

#define __trace__ printf(" -> %s:%d %s\n", __FILE__, __LINE__, __func__); fflush(NULL);

/* based on: http://stackoverflow.com/a/7776146 */
static void
hexdump (std::string desc, std::string data) {

    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)data.c_str();

	std::cout << desc << ":" << std::endl;

	unsigned int i;
    for (i = 0; i < data.size(); i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

#endif // _MIBAND_DEBUG_H_
