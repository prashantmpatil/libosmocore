/*! \file gsm_04_12.h
 * GSM TS 04.12 definitions for Short Message Service Cell Broadcast. */

#pragma once

#include <stdint.h>
#include <osmocom/core/endian.h>

#define GSM412_MSG_LEN		88	/* TS 04.12 Section 3.1 */
#define GSM412_BLOCK_LEN	22	/* TS 04.12 Section 3.1 */

#define GSM412_SEQ_FST_BLOCK		0x0
#define GSM412_SEQ_SND_BLOCK		0x1
#define GSM412_SEQ_TRD_BLOCK		0x2
#define GSM412_SEQ_FTH_BLOCK		0x3
#define GSM412_SEQ_FST_SCHED_BLOCK	0x8
#define GSM412_SEQ_NULL_MSG		0xf

struct gsm412_block_type {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	seq_nr : 4,
		lb : 1,
		lpd : 2,
		spare : 1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t	spare:1, lpd:2, lb:1, seq_nr:4;
#endif
} __attribute__((packed));

struct gsm412_sched_msg {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t beg_slot_nr : 6,
		type : 2;
	uint8_t end_slot_nr : 6,
		spare1 : 1, spare2: 1;
	uint8_t cbsms_msg_map[6];
	uint8_t data[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t type:2, beg_slot_nr:6;
	uint8_t spare2:1, spare1:1, end_slot_nr:6;
	uint8_t cbsms_msg_map[6];
	uint8_t data[0];
#endif
} __attribute__((packed));

/* Section 9.3: ?? */

/* 9.3.24: Warning Tyoe */
#define GSM412_WARN_TYPE_EARTHQUAKE		0x00
#define GSM412_WARN_TYPE_TSUNAMI		0x01
#define GSM412_WARN_TYPE_QUAKE_ANDTSUNAMI	0x02
#define GSM412_WARN_TYPE_TEST			0x03
#define GSM412_WARN_TYPE_OTHER			0x04
struct gsm412_warning_type {
	uint16_t warning_type:7,
		 emerg_user_alert:1,
		 popup:1,
		 padding:7;
} __attribute__((packed));


/* 9.3.25 */
struct gsm412_warning_sec_info {
	uint8_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	uint8_t timezone;
	uint8_t signature[43];
} __attribute__((packed));

/* Section 9.4: Message Format on the Radio Network - MS/UE Interface */

/* 9.4.1.2.1 Serial Number */
#define GSM412_SERNR_GS_CELL_IMM	0
#define GSM412_SERNR_GS_PLMN_NORM	1
#define GSM412_SERNR_GS_LA_SA_TA_NORM	2
#define GSM412_SERNR_GS_CELL_NORM	3

struct gsm412_9_serial_nr {
	uint16_t	gs:2,
			msg_code:10,
			update_nr: 4;
} __attribute__((packed));

/* 9.4.1.2.4 Page Parameter */
struct gsm412_9_page_param {
	uint8_t		total_pages:4,
			page_nr:4;
} __attribute__((packed));

/* 9.4.1.2 Message Parameter */
struct gsm412_9_message {
	struct gsm412_9_serial_nr	ser_nr;		/* 9.4.1.2.1 */
	uint16_t			msg_id;		/* 9.4.1.2.2 */
	uint8_t				dcs;		/* TS 23.038 */
	struct gsm412_9_page_param	page_param;	/* 9.4.1.2.4 */
	uint8_t				content[0];	/* byte 7..88, i.e. 0-82 octets */
} __attribute__((packed));

/* 9.4.1.3 ETWS Primary Notification Message */
struct gsm412_9_etws_prim_notif_msg {
	struct gsm412_9_serial_nr	ser_nr;		/* 9.4.1.2.1 */
	uint16_t			msg_id;		/* 9.4.1.2.2 */
	struct gsm412_warning_type	warning_type;	/* 9.3.24 */
	uint8_t				warning_sec_info[50]; /* 9.3.25 */
} __attribute__((packed));


//struct gsm412_
