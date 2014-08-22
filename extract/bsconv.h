/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: bsconv.h,v 0d6e5d383a92 2010/08/27 04:28:27 Hirochika $ */

#ifndef _BSCONV_H
#define _BSCONV_H

#include <stdint.h>

enum _endian {
    _ENDIAN_MACHINE,
    _ENDIAN_NETWORK,
};

#ifdef __cplusplus
extern "C" {
#endif

    uint16_t bs2uint16(const unsigned char *, enum _endian);
    uint32_t bs2uint32(const unsigned char *, enum _endian);

#ifdef __cplusplus
}
#endif

#endif /* _BSCONV_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
