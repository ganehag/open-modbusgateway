AC_INIT([modbusgateway],[0.1],[mikael.brorsson@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

COMPILER_FLAGS

AC_LANG([C])

AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug],
                 [enable debug mode])],
                 [enable_debug=$enableval], [enable_debug=no])

if test "x$enable_debug" = "xyes"; then
  CFLAGS="$CFLAGS -g -DDEBUG"
fi

# Check for programs
AC_PROG_CC
PKG_PROG_PKG_CONFIG

# libmodbus
PKG_CHECK_MODULES([MODBUS], [libmodbus >= 3.1.4], dummy=yes,
  AC_MSG_ERROR("required libmodbus >= 3.1.4"))
AC_SUBST(MODBUS_CFLAGS)
AC_SUBST(MODBUS_LIBS)
AC_SUBST(MODBUS_LDFLAGS)

# libmosquitto
PKG_CHECK_MODULES([MOSQUITTO], [libmosquitto >= 1.4], dummy=yes,
  AC_MSG_ERROR("required libmosquitto >= 1.4"))
AC_SUBST([MOSQUITTO_CFLAGS])
AC_SUBST([MOSQUITTO_LIBS])
AC_SUBST([MOSQUITTO_LDFLAGS])

# Check for headers
AC_CHECK_HEADERS([pthread.h], dummy=yes,
  AC_MSG_ERROR("required header pthread.h not found"))

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
