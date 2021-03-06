
# This is an example site-level customization file for cado-nfs. It is
# the recommended way of setting parameters to the build system. The same
# effect can be achieved with environment variables.
#
# This file is sourced as a bourne shell script within the build process
# (by scripts/call_cmake.sh, precisely). Therefore, all variables setting
# must obey the normal quoting construct for shell variables, e.g.
# CFLAGS="-g -O2"
# Note also that for the same reason, you may use conditional variable
# setting in the syntax recognized by most shells, which is
# : ${CFLAGS:="-g -O2"}
# This means ``set CFLAGS to "-g -O2" unless it is already set to something
# (by an environment variable, that is).
#
# The flags recognized by the build process are a restrictive list. Don't
# even hope for something to be recognized if it's neither documented
# here nor mentioned in any of the scripts/call_cmake.sh or
# */CMakeLists.txt files.

# It is perfectly normal to leave most values undefined here, as it is
# hoped that the default settings work correctly. The intent of the
# variable settings here is to accomodate special needs.
#
# Setting a variable to an empty value or leaving it unset are equivalent
# here.
#
# Example values are given for all flags. The first example corresponds
# to the default setting.

############################################################
# build_tree: where do the object files go.
#
# Example values:
# build_tree="${up_path}/build/`hostname`"
# build_tree="${up_path}/build/`uname -m`"
# build_tree=/tmp/cado-nfs-build
#
# up_path, amongst other variables, is defined from the caller script
# which is scripts/call_cmake.sh.
#
# build_tree must be set unconditionally (that is, in contrast to the
# other variables, you can't do : ${build_tree:=blah blah blah)
#
# It is possible, in local.sh, to vary the build tree depending on the
# environment variables (when you pass such variables in an external
# fashion, as in: MPI=1 DEBUG=1 make). By default cado-nfs does so if MPI
# is defined (it makes sure that $build_tree contains .mpi). More
# generally, you may do within local.sh:
# if [ "$CLANG" ] ; then
#     CC=clang
#     CXX=clang++
#     build_tree="${build_tree}.clang"
# fi
#
# Other suggestions:
#
# if [ "$MPI" ] ; then
#     # build_tree already contains a ".mpi" suffix in that case, added
#     # by scripts/call_cmake.sh ; but we can add more.
#     case "$MPI" in
#         *mvapich2*) build_tree="${build_tree}.mvapich2";;
#         *openmpi*) build_tree="${build_tree}.openmpi";;
#     esac
# fi
# if [ "$DEBUG" ] ; then
#     build_tree="${build_tree}.debug"
#     # Dangerous pitfall -- mpicc has the nasty habit of forcing -O2 !
#     CFLAGS="-O0 -g"
#     CXXFLAGS="-O0 -g"
# fi

############################################################
# CC: C Compiler
#
# Example values:
# CC=
# CC=gcc
# CC=/usr/local/bin/gcc
# CC=icc
# CC="$HOME/bin/cc"
#
# The user is advised against setting $CC as a path + some switches, such
# as "gcc -m64". This may or may not work.

############################################################
# CXX: C++ Compiler (cado-nfs contains a few C++ programs)
#
# Example values:
# CXX=
# CXX=/usr/local/bin/g++

############################################################
# CFLAGS: Flags for compiling C programs
#
# Example values:
# CFLAGS=-O2
CFLAGS="-O3 -march=native -funroll-loops -DNDEBUG"
# CFLAGS=-g
# CFLAGS="-O2 -DNDEBUG"
#
# Note: the default value of CFLAGS is "-O2". If you want to disable
# the ASSERT() tests, define CFLAGS="-O2 -DNDEBUG". This should provide a
# small speed-up (don't expect too much improvement, though).
#
# Note that some flags, and some compile-time definitions are added
# anyway and cannot be overridden. For example, one cannot remove
# -std=c99 for CFLAGS if GNU C is being used, because its use is
# mandatory. We also do this for the Intel compiler icc.

############################################################
# CXXFLAGS: Flags for compiling C++ programs
#
# Example values:
# CXXFLAGS=-O2
# CXXFLAGS=-g
# CXXFLAGS="-O2 -DNDEBUG"
CXXFLAGS="-O3 -march=native -funroll-loops -DNDEBUG"
# CXXFLAGS="-O3 -funroll-loops -DNDEBUG -Wno-empty-body"
#
# Important note: CXXFLAGS lives totally independently of CFLAGS.
# Therefore if some flag is relevant to both, you have to set both.

############################################################
# ENABLE_SHARED: Disable shared libraries
# Setting this to 1 causes CADO to use shared libraries for CADO convenience
# libraries and for the BWC arithmetic functions. This decreases build time
# and binary file size, but the resulting binaries are less portable.
# Mostly meant for development purposes.
# ENABLE_SHARED=0

############################################################
# PREFIX: Installation path
#
# Example values:
# PREFIX=<path-to-source-tree>/installed
PREFIX=/usr/local/cado
#
# This is for ``make install'': binaries will be installed in $PREFIX/bin.

############################################################
# CADO_VERSION_STRING: set package version
#
# This is relevant only for the development tree. It is documented here
# for completeness, but cado-nfs tarballs lack the scripts which
# understand this variable.

############################################################
# GF2X_CONFIGURE_FLAGS: pass flags to gf2x's ./configure script.
#
# Example values:
# GF2X_CONFIGURE_FLAGS="--silent --disable-shared"


############################################################
# GMP: prefix to installed GMP, or path to built GMP source tree.
#
# (GMP is a requirement)
#
# Example values:
# GMP=
# GMP=/usr/local/gmp-5.1.0
# GMP=$HOME/gmp-5.1.0
#
# It does not matter whether $GMP points to the ``prefix'' where some GMP
# version has been installed (with make install), or whether $GMP points
# to a built source tree. The build system is supposed to correctly
# locate include files and libraries in both cases. However, to
# accomodate special configurations, one may also use the two extra
# variables:
#
# GMP_LIBDIR=/some/directory
# GMP_INCDIR=/some/directory

############################################################
# HWLOC: prefix to installed hwloc
#
# (HWLOC is optional)
#
# Example values:
# HWLOC=$HOME/Packages/hwloc-1.11.1
#
# To accomodate special configurations, one may also use the two extra
# variables:
# HWLOC_LIBDIR=/some/directory
# HWLOC_INCDIR=/some/directory

############################################################
# GMPECM: prefix to installed gmp-ecm
#
# (GMPECM is optional, but required for JL selection polynomial dlp)
#
# Example values:
# GMPECM=$HOME/Packages/ecm-42.17.0
#
# To accomodate special configurations, one may also use the two extra
# variables:
# GMPECM_LIBDIR=/some/directory
# GMPECM_INCDIR=/some/other/directory

############################################################
# CURL: prefix to installed Curl
#
# (Curl is optional)
#
# Example values:
# curl=/usr/local
#
# To accomodate special configurations, one may also use the two extra
# variables:
# CURL_LIBDIR=/some/directory
# CURL_INCDIR=/some/directory

############################################################
# MPI: Whether to use MPI (Message Passing Interface) or not
#
# (MPI is optional)
#
# Example values:
# MPI=0
MPI=1
# MPI=/usr/local/mpich2-1.0.8p1/
# MPI=/usr/local/openmpi-1.3.0/
# MPI=$HOME/mpich2-1.0.8p1
# OMPI_CC=gcc44
# OMPI_CXX=g++44
#
# Some cado-nfs programs can work with MPI. To build MPI-enabled tools,
# set $MPI to 1. The default value is unset, which effectively disables
# MPI (and activate stubs for the corresponding functions).
#
# Setting $MPI to 1 means to enable an MPI build, using the system-level
# default MPI compiler (the one pointed to by `which mpicc`).
#
# Setting $MPI to a path instructs the build process to look for the
# compiler $MPI/mpicc, or $MPI/bin/mpicc.
#
# Note that in any case, for the MPI build to be enabled, it is necessary
# for an MPI C compiler AND an MPI C++ compiler AND an mpiexec program to
# be found.
#
# ``MPI=1'', ``MPI=yes'', ``MPI=on'', are equivalent.
# ``MPI=0'', ``MPI=no'', ``MPI=off'', are equivalent.
#
# By default, mpicc calls the default compiler (gcc or g++) installed on your
# computer. If this default compiler is too old or buggy, you might want to use
# OMPI_CC and/or OMPI_CXX to specify a newer compiler (this is for Open MPI).

############################################################
# Python: Whether to test for a Python 3 interpreter or not
# 
# The cado-nfs.py script needs Python 3 and the sqlite3
# module. If you do not wish to use cado-nfs.py, set
# NO_PYTHON_CHECK to a non-empty string to disable testing
# for Python 3 and sqlite in the CMake configuration
#
# NO_PYTHON_CHECK="foo"

############################################################
# For big factorizations, increase the size of variable.
# If you want to use large prime bound > 32, uncomment the following line
FLAGS_SIZE="-DSIZEOF_P_R_VALUES=8"
# If you want to be able to handle more than 2^32 ideals in your factor base or
# have more than 2^32 relations (for large prime bound > 35 or 36), uncomment
# the following line
FLAGS_SIZE="-DSIZEOF_P_R_VALUES=8 -DSIZEOF_INDEX=8"
