#
# Copyright (C) 2015 MediaTek Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#

$(warning harry MTK_PLATFORM is $(MTK_PLATFORM) filter $(filter $(MTK_PLATFORM), mt8163))
# common driver code for CMDQ
ifeq ($(CONFIG_MTK_CMDQ_TAB), y)
  ifneq (,$(filter $(MTK_PLATFORM), mt8163))
    $(warning harry build cmdq hv1)
    obj-y += hv1/
  else
    $(warning harry build cmdq v2)
    obj-y += v2/
  endif
else
  # use common driver
  obj-y += v3/
endif
# mdp_sw_sync
obj-y += mdp_sync/
# EOF
