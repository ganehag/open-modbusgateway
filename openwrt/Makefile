include $(TOPDIR)/rules.mk

PKG_NAME:=open-modbusgateway
PKG_VERSION:=0.3.0
PKG_RELEASE:=1
PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=LICENSE

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_SOURCE_PROTO:=git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/ganehag/open-modbusgateway.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/open-modbusgateway
    SECTION:=net
    CATEGORY:=Network
    TITLE:=Open Modbus Gateway
    DEPENDS:=+libmosquitto +libmodbus
    MAINTAINER:=Mikael Ganehag Brorsson <mikael.brorsson@gmail.com>
endef

define Package/open-modbusgateway/description
	An Open Source alternative to Teltonikas' Modbus Gateway.
endef

define Package/open-modbusgateway/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/openmmg.config $(1)/etc/config/openmmg
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/openmmg.init $(1)/etc/init.d/openmmg
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/openmmg $(1)/usr/bin/openmmg
endef

$(eval $(call BuildPackage,open-modbusgateway))
