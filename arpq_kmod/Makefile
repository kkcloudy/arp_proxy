#
# Copyright (C) 2008-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=arpq_kmod
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/arpq_kmod
  SECTION:=hos
  CATEGORY:=hos
  SUBMENU:=kmods
  TITLE:=ARPQ Kmod Compile
  FILES:=$(PKG_BUILD_DIR)/arpq_kmod.ko
  AUTOLOAD:=$(call AutoLoad,30,arpq_kmod)
  KCONFIG:=
endef

define KernelPackage/arpq_kmod/description
	ARP nfqueue Kernel Module
endef

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,arpq_kmod))
