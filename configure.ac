AC_INIT([libosmo-gprs],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[osmocom-net-gprs@lists.osmocom.org])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_TESTDIR(tests)

AM_INIT_AUTOMAKE([dist-bzip2])

CFLAGS="$CFLAGS -std=gnu11"

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl checks for libraries
PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 1.7.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 1.7.0)

dnl checks for header files
AC_HEADER_STDC

dnl Checks for typedefs, structures and compiler characteristics

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Werror=implicit-int -Werror=int-conversion -Werror=old-style-definition"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([libosmo-csn1.pc
		 libosmo-gprs-gmm.pc
		 libosmo-gprs-llc.pc
		 libosmo-gprs-rlcmac.pc
		 libosmo-gprs-sndcp.pc
		 include/Makefile
		 include/osmocom/Makefile
		 include/osmocom/csn1/Makefile
		 include/osmocom/gprs/Makefile
		 include/osmocom/gprs/gmm/Makefile
		 include/osmocom/gprs/llc/Makefile
		 include/osmocom/gprs/rlcmac/Makefile
		 include/osmocom/gprs/sndcp/Makefile
		 src/Makefile
		 src/csn1/Makefile
		 src/gmm/Makefile
		 src/llc/Makefile
		 src/rlcmac/Makefile
		 src/sndcp/Makefile
		 tests/Makefile
		 tests/gmm/Makefile
		 tests/llc/Makefile
		 tests/rlcmac/Makefile
		 tests/sndcp/Makefile
		 Makefile
		 contrib/libosmo-gprs.spec])
AC_OUTPUT
