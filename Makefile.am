#
# $Id: Makefile.am,v 0d6e5d383a92 2010/08/27 04:28:27 Hirochika $
#
# Copyright (c) 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
# Authors:
#      Hirochika Asai  <asai@scyphus.co.jp>
#

EXTRA_DIST = scripts/sequence.sh scripts/chssh.sh scripts/path2gal.py\
	scripts/sequence.py scripts/asn.py scripts/rel2gal.py scripts/caida.sh \
	scripts/chssh2012.sh scripts/pathcount.py

bin_PROGRAMS = extract-rib infer-asrel-gao path2gal path2gal_inet

extract_rib_SOURCES = extract/extract-rib.c extract/mrt.c extract/mrt.h \
	extract/bsconv.c extract/bsconv.h

path2gal_SOURCES = extract/path2gal.c
path2gal_inet_SOURCES = extract/path2gal_inet.c

infer_asrel_gao_SOURCES = gao/infer-asrel-gao.c gao/gao.c gao/gao.h

CLEANFILES = *~
