AC_INIT([modbusgateway], [0.1], [mikael.brorsson@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Check for programs
AC_PROG_CC
PKG_PROG_PKG_CONFIG

# Check for libraries
PKG_CHECK_MODULES(MODBUS, libmodbus >= 3.1.4, dummy=yes,
  AC_MSG_ERROR("required libmodbus >= 3.1.4"))
AC_SUBST(MODBUS_CFLAGS)
AC_SUBST(MODBUS_LIBS)

PKG_CHECK_MODULES(MOSQUITTO, libmosquitto >= 1.4.0, dummy=yes,
  AC_MSG_ERROR("required libmosquitto >= 1.4.0"))
AC_SUBST(MOSQUITTO_CFLAGS)
AC_SUBST(MOSQUITTO_LIBS)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
