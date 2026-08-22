AC_INIT([modbusgateway],[0.4.0],[mikael.brorsson@gmail.com])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_USE_SYSTEM_EXTENSIONS

AC_LANG([C])

AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug],
                 [enable debug mode])],
                 [enable_debug=$enableval], [enable_debug=no])

AC_ARG_ENABLE([tests], [AS_HELP_STRING([--disable-tests],
                 [do not build the CUnit test suite])],
                 [enable_tests=$enableval], [enable_tests=yes])

AC_ARG_ENABLE([lua], [AS_HELP_STRING([--enable-lua],
                 [build Lua automation support])],
                 [enable_lua=$enableval], [enable_lua=no])

if test "x$enable_debug" = "xyes"; then
  CFLAGS="$CFLAGS -g -DDEBUG"
fi

# Check for programs
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AM_CONDITIONAL([BUILD_TESTS], [test "x$enable_tests" = "xyes"])
AM_CONDITIONAL([BUILD_LUA], [test "x$enable_lua" = "xyes"])
if test "x$enable_tests" = "xyes"; then
  PKG_CHECK_MODULES([CUNIT], [cunit >= 2.1.3], dummy=yes,
    AC_MSG_ERROR("required CUnit >= 2.1.3"))
fi
if test "x$enable_lua" = "xyes"; then
  AC_MSG_CHECKING([for Lua 5.1 through 5.4])
  lua_pkg=""
  for candidate in lua5.4 lua5.3 lua5.2 lua5.1; do
    if $PKG_CONFIG --exists "$candidate"; then
      lua_pkg="$candidate"
      break
    fi
  done
  if test -z "$lua_pkg"; then
    AC_MSG_FAILURE([Lua 5.1, 5.2, 5.3, or 5.4 is required with --enable-lua])
  fi
  LUA_CFLAGS=`$PKG_CONFIG --cflags "$lua_pkg"`
  LUA_LIBS=`$PKG_CONFIG --libs "$lua_pkg"`
  AC_DEFINE([HAVE_LUA_AUTOMATION], [1], [Define when Lua automation is enabled])
  AC_MSG_RESULT([$lua_pkg])
fi
AC_SUBST([LUA_CFLAGS])
AC_SUBST([LUA_LIBS])

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
  test/Makefile
])
AC_OUTPUT
