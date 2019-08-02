
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
#include "cmdq_fs.h"
#include "cmdq_core.h"
/*internal use*/
static void fs_create(struct fs_struct *file, const char *fileName);
static void fs_write(struct fs_struct *file, char *buffer);
static void fs_close(struct fs_struct *file);

void init_fs_struct(struct fs_struct *file)
{
	file->fs = 0;
	file->fp = NULL;
	file->fs_create = fs_create;
	file->fs_write = fs_write;
	file->fs_close = fs_close;
}


void fs_create(struct fs_struct *file, const char *fileName)
{
	if (fileName == NULL || *fileName == '\0') {
		CMDQ_ERR("illegal fileName\n");
		return;
	}
	file->fs = get_fs();
	set_fs(KERNEL_DS);
	file->fp = filp_open(fileName, O_RDWR | O_CREAT | O_TRUNC, 0x644);
	if (IS_ERR(file->fp))
		CMDQ_ERR("create file[%s] error, fp[%p]\n",
			fileName,
			file->fp);
	else
		CMDQ_MSG("create file[%s] success, fp[%p]\n",
			fileName,
			file->fp);
}

void fs_write(struct fs_struct *file, char *buffer)
{
	file->fp->f_op->write(file->fp,
		buffer,
		strlen(buffer),
		&file->fp->f_pos);
}

void fs_close(struct fs_struct *file)
{
	if (file->fp)
		filp_close(file->fp, NULL);
	set_fs(file->fs);
}
