include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=arp-proxy
PKG_VERSION:=2016.4.7
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

export FILENO_PATH=$(TOPDIR)/fileno/$(TARGET_DIR_NAME)
export FILENO_BIN=$(SCRIPT_DIR)/fileno

define Package/arp-proxy
  SECTION:=hos
  CATEGORY:=hos
  SUBMENU:=apps
  DEPENDS:=+qca-hostap-10.4 +libnetfilter-queue +libnfnetlink
  TITLE:=ARP Proxy
endef

define Package/arp-proxy/description
	ARP Proxy
endef


#TARGET_CFLAGS += \
#	-I$(AUTELAN_LIBS)
#	-I$(STAGING_DIR)/usr/include \

#TARGET_LDFLAGS += \
#	-L$(STAGING_DIR)/usr/lib
define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) ./src/* $(PKG_BUILD_DIR)/src
endef
		
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src/ \
	CC="$(TARGET_CC)" \
	AR=$(TARGET_CROSS)ar \
	STAGING_DIR="$(STAGING_DIR)" \
	BUILD_DIR="$(BUILD_DIR)"
endef

define Package/arp-proxy/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/arp-proxy $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/arpp_cli $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/arp-proxy $(1)/etc/init.d/arp-proxy
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/arp-proxy.conf $(1)/etc/config/arp-proxy
	$(INSTALL_DIR) $(1)/bin
	$(CP) ./files/libnetfilter_queue.so.1 $(1)/bin/
endef

$(eval $(call BuildPackage,arp-proxy))
