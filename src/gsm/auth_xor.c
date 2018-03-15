/*! \file auth_xor.c
 * GSM/GPRS/3G authentication core infrastructure */
/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Daniel Willmann <dwillmann@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <osmocom/crypt/auth.h>
#include <string.h>
#include <errno.h>

/*! \addtogroup auth
 *  @{
 */

static void xor(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		out[i] = a[i] ^ b[i];
}

/* 3GPP TS 34.108 8.1.2.1 XOR auth procedure */
static int xor_gen_vec(struct osmo_auth_vector *vec,
	struct osmo_sub_auth_data *aud, const uint8_t *_rand)
{
	uint8_t xdout[16], ak[6], cdout[8], xmac[8];
	/* res[16], ck[16], ik[16],*/
	int i;

	/* Step 1: xdout = ki XOR rand */
	if (aud->type == OSMO_AUTH_TYPE_GSM)
		xor(xdout, aud->u.gsm.ki, _rand, sizeof(xdout));
	else if (aud->type == OSMO_AUTH_TYPE_UMTS)
		xor(xdout, aud->u.umts.k, _rand, sizeof(xdout));
	else
		return -ENOTSUP;

	/**
	 * Step 2: res = xdout
	 *
	 * Suggested length for res is 128 bits, i.e. 16 bytes,
	 * but also can be in range: 30 < n < 128 bits.
	 */
	memcpy(vec->res, xdout, sizeof(xdout));
	vec->res_len = 16;

	/* ck = xdout[1-15,0] */
	memcpy(vec->ck, xdout + 1, sizeof(xdout) - 1);
	vec->ck[15] = xdout[0];

	/* ik = xdout[2-15,0-1] */
	memcpy(vec->ik, xdout + 2, sizeof(xdout) - 2);
	memcpy(vec->ik + 14, xdout, 2);

	/* ak = xdout[3-8] */
	memcpy(ak, xdout + 3, sizeof(ak));

	/**
	 * 3GPP TS 33.102, clause 6.8.1.2, b
	 * sres = c2(res) = res[0-3] ^ res[4-7] ^ res[8-11] ^ res[12-15]
	 */
	for (i = 0; i < 4; i++) {
		vec->sres[i]  = vec->res[i] ^ vec->res[i + 4];
		vec->sres[i] ^= vec->res[i + 8] ^ vec->res[i + 12];
	}

	/**
	 * 3GPP TS 33.102, clause 6.8.1.2, c
	 * kc = c3(ck, ik) = ck[0-3] ^ ck[4-7] ^ ik[0-3] ^ ik[4-7]
	 */
	for (i = 0; i < 8; i++) {
		vec->kc[i]  = vec->ck[i] ^ vec->ck[i + 8];
		vec->kc[i] ^= vec->ik[i] ^ vec->ik[i + 8];
	}

	/* The further part is UMTS specific */
	if (aud->type != OSMO_AUTH_TYPE_UMTS) {
		vec->auth_types = OSMO_AUTH_TYPE_GSM;
		return 0;
	}

	/**
	 * Step 3: cdout = sqn[0-5] || amf[0-1]
	 *
	 * FIXME: The aud->u.umts.sqn has uint64_t type,
	 * so 8 bytes long. We take 6 bytes from *the beginning*
	 * of sqn, but shouldn't we shift it first?
	 * I.e. aud->u.umts.sqn << 2
	 *
	 * And what about byte order??
	 */
	memcpy(cdout, (uint8_t *) &aud->u.umts.sqn, 6);
	memcpy(cdout + 6, aud->u.umts.amf, 2);

	/* Step 4: xmac = xdout[0-8] XOR cdout[0-8] */
	xor(xmac, xdout, cdout, sizeof(xmac));

	/**
	 * Step 5: autn = sqn XOR ak || amf || mac
	 *
	 * FIXME: The aud->u.umts.sqn has uint64_t type,
	 * so 8 bytes long. We take 6 bytes from *the beginning*
	 * of sqn, but shouldn't we shift it first?
	 * I.e. aud->u.umts.sqn << 2
	 *
	 * And what about byte order??
	 */
	xor(vec->autn, (uint8_t *) &aud->u.umts.sqn, ak, sizeof(ak));
	memcpy(vec->autn + 6, aud->u.umts.amf, 2);
	memcpy(vec->autn + 8, xmac, sizeof(xmac));

	vec->auth_types = OSMO_AUTH_TYPE_UMTS | OSMO_AUTH_TYPE_GSM;

	return 0;
}

static struct osmo_auth_impl xor_alg = {
	.algo = OSMO_AUTH_ALG_XOR,
	.name = "XOR (libosmogsm built-in)",
	.priority = 1000,
	.gen_vec = &xor_gen_vec,
};

static __attribute__((constructor)) void on_dso_load_xor(void)
{
	osmo_auth_register(&xor_alg);
}

/*! @} */
