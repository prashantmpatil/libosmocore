/*! \file aes.h
 * AES functions */
/*
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * See README and COPYING for more details.
 */

#pragma once

#define AES_BLOCK_SIZE 16

void * aes_encrypt_init(const u8 *key, size_t len);
void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt);
void aes_encrypt_deinit(void *ctx);
void * aes_decrypt_init(const u8 *key, size_t len);
void aes_decrypt(void *ctx, const u8 *crypt, u8 *plain);
void aes_decrypt_deinit(void *ctx);
