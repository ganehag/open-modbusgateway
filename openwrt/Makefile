include $(TOPDIR)/rules.mk

PKG_NAME:=open-modbusgateway
PKG_VERSION:=0.1.2
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
    DEPENDS:=+libmosquitto +libmodbus +lpthreads
    MAINTAINER:=Mikael Ganehag Brorsson <mikael.brorsson@gmail.com>
endef

define Package/open-modbusgateway/description
	An Open Source alternative to Teltonikas' Modbus Gateway.
endef

define Package/open-modbusgateway/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/modbusgateway.conf $(1)/etc/config/modbusgateway
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/modbusgateway.init $(1)/etc/init.d/modbusgateway
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/modbusgateway $(1)/usr/sbin/modbusgateway
endef

$(eval $(call BuildPackage,open-modbusgateway))

