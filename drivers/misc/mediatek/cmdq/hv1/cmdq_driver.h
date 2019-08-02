
/*
 * Copyright (C) 2018 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef __CMDQ_DRIVER_H__
#define __CMDQ_DRIVER_H__

#include <linux/kernel.h>
#include "cmdq_def.h"

struct cmdqUsageInfoStruct {
	/* [OUT] current engine ref count */
	uint32_t count[CMDQ_MAX_ENGINE_COUNT];
};

struct cmdqJobStruct {
	/* [IN] the job to perform */
	struct cmdqCommandStruct command;
	/* [OUT] handle to resulting job */
	cmdqJobHandle_t hJob;
};

struct cmdqJobResultStruct {
	/* [IN]  Job handle from CMDQ_IOCTL_ASYNC_JOB_EXEC */
	cmdqJobHandle_t hJob;
	/* [OUT] engine flag passed down originally */
	uint64_t engineFlag;
	/* [IN/OUT] read register values, if any. */
	struct cmdqRegValueStruct regValue;
	/*as input, the "count" field must represent */
	/*buffer space pointed by "regValues". */
	/*Upon return, CMDQ driver fills "count" with */
	/*actual requested register count. */
	/*However, if the input "count" is too small, */
	/*-ENOMEM is returned, and "count" is filled*/
	/*with requested register count. */
	/* [IN/OUT] physical address to read */
	struct cmdqReadAddressStruct readAddress;
};

struct cmdqWriteAddressStruct {
	/* [IN] count of the writable buffer
	 * (unit is # of uint32_t, NOT in byte)
	 */
	uint32_t count;
	/* [OUT] When Alloc, this is the resulting PA.
	 * It is guaranteed to be continuous.
	 * [IN]  When Free, please pass returned address down to ioctl.
	 *
	 * indeed param startPA should be UNSIGNED LONG type for 64 bit kernel.
	 * Considering our plartform supports max
	 * 4GB RAM(upper-32bit don't care for SW)
	 * and consistent common code interface, remain uint32_t type.
	 * [OUT] When Alloc, this is the resulting PA.
	 * It is guaranteed to be continuous.
	 */
	uint32_t startPA;
	/* [IN]  When Free, please pass returned address down to ioctl. */
};

#define CMDQ_IOCTL_MAGIC_NUMBER 'x'

#define CMDQ_IOCTL_LOCK_MUTEX   _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	1, \
	int)
#define CMDQ_IOCTL_UNLOCK_MUTEX _IOR(CMDQ_IOCTL_MAGIC_NUMBER, \
	2, \
	int)
#define CMDQ_IOCTL_EXEC_COMMAND _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	3, \
	struct cmdqCommandStruct)
#define CMDQ_IOCTL_QUERY_USAGE  _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	4, \
	struct cmdqUsageInfoStruct)

/* Async operations */
#define CMDQ_IOCTL_ASYNC_JOB_EXEC _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	5, \
	struct cmdqJobStruct)

#define CMDQ_IOCTL_ASYNC_JOB_WAIT_AND_CLOSE _IOR(CMDQ_IOCTL_MAGIC_NUMBER, \
	6, \
	struct cmdqJobResultStruct)

#define CMDQ_IOCTL_ALLOC_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	7, \
	struct cmdqWriteAddressStruct)
#define CMDQ_IOCTL_FREE_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	8, \
	struct cmdqWriteAddressStruct)
#define CMDQ_IOCTL_READ_ADDRESS_VALUE _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	9, \
	struct cmdqReadAddressStruct)

/*
 * Chip capability query. output parameter is a bit field.
 * Bit definition is enum CMDQ_CAP_BITS.
 */
#define CMDQ_IOCTL_QUERY_CAP_BITS _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
	10, \
	int)

/* copy HDCP version from src handle to dst handle */
#define CMDQ_IOCTL_SYNC_BUF_HDCP_VERSION _IOW(CMDQ_IOCTL_MAGIC_NUMBER, \
		11, \
		struct cmdqSyncHandleHdcpStruct)


#endif				/* __CMDQ_DRIVER_H__ */
