/*
 * This file contains several sample settings especially for Windows
 * Mobile and Symbian targets. You can include this file in your
 * <pj/config_site.h> file.
 *
 * The Windows Mobile and Symbian settings will be activated
 * automatically if you include this file.
 *
 * In addition, you may specify one of these macros (before including
 * this file) to activate additional settings:
 *
 * #define PJ_CONFIG_NOKIA_APS_DIRECT
 *   Use this macro to activate the APS-Direct feature. Please see
 *   http://trac.pjsip.org/repos/wiki/Nokia_APS_VAS_Direct for more
 *   info.
 *
 * #define PJ_CONFIG_WIN32_WMME_DIRECT
 *   Configuration to activate "APS-Direct" media mode on Windows or
 *   Windows Mobile, useful for testing purposes only.
 */

/* Default configuration for Carrier */

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

/*
 * PJLIB settings.
 */

/* Both armv6 and armv7 has FP hardware support.
 * See https://trac.pjsip.org/repos/ticket/1589 for more info
 */
#define PJ_HAS_FLOATING_POINT       1

/*
 * PJMEDIA settings
 */

/* Select codecs to disable */
#define PJMEDIA_HAS_L16_CODEC       0
#define PJMEDIA_HAS_ILBC_CODEC      0
#define PJMEDIA_ILBC_CODEC_USE_COREAUDIO    0

/* We probably need more buffers, so increase the limit */
// #define PJMEDIA_SOUND_BUFFER_COUNT      32

/* Fine tune Speex's default settings for best performance/quality */
#define PJMEDIA_CODEC_SPEEX_DEFAULT_QUALITY 5

#   define PJ_ICE_MAX_CHECKS		   64

#ifndef PJMEDIA_HAS_SPEEX_AEC
    /* For CPU reason, disable speex AEC and use the echo suppressor. */
    #if defined(_WIN32) || defined(_WIN64)
        #define PJMEDIA_HAS_SPEEX_AEC       1
    #endif

    #if defined(__linux__)
        #define PJMEDIA_HAS_SPEEX_AEC       1
    #endif

    #if defined(__ANDROID__)
        #undef PJMEDIA_HAS_SPEEX_AEC
        #define PJMEDIA_HAS_SPEEX_AEC       0
    #endif

    #if defined(__APPLE__)
        #if TARGET_OS_MAC
            #define PJMEDIA_HAS_SPEEX_AEC   1
        #else
            #define PJMEDIA_HAS_SPEEX_AEC   0
        #endif
    #endif
#endif

/*
 * PJNATH settings.
 */
#define PJ_STUN_SOCK_PKT_LEN            2176
/*
 * PJSIP settings.
 */

/* Increase allowable packet size, just in case */
//#define PJSIP_MAX_PKT_LEN         2000

/*
 * PJSUA settings.
 */

/* Default codec quality, previously was set to 5, however it is now
 * set to 4 to make sure pjsua instantiates resampler with small filter.
 */
#define PJSUA_DEFAULT_CODEC_QUALITY     4

/* Set maximum number of dialog/transaction/calls to minimum */
#define PJSIP_MAX_TSX_COUNT         31
#define PJSIP_MAX_DIALOG_COUNT      31
#define PJSUA_MAX_CALLS             8

/* Other pjsua settings */
#define PJSUA_MAX_ACC               4
#define PJSUA_MAX_PLAYERS           4
#define PJSUA_MAX_RECORDERS         4
#define PJSUA_MAX_CONF_PORTS        (PJSUA_MAX_CALLS+2*PJSUA_MAX_PLAYERS)
#define PJSUA_MAX_BUDDIES           32

#if defined(__ANDROID__)
    #define PJ_ANDROID              1

    /*
     * PJLIB settings.
     */

    /* Disable floating point support */
    #undef PJ_HAS_FLOATING_POINT
    #define PJ_HAS_FLOATING_POINT   0
#endif

#if defined(__APPLE__)
    #define PJ_HAS_FLOATING_POINT   1
#endif
