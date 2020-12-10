/*
 * Copyright (c) 2018 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __ELASTOS_CARRIER_H__
#define __ELASTOS_CARRIER_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>

#if defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CARRIER_STATIC)
  #define CARRIER_API
#elif defined(CARRIER_DYNAMIC)
  #ifdef CARRIER_BUILD
    #if defined(_WIN32) || defined(_WIN64)
      #define CARRIER_API        __declspec(dllexport)
    #else
      #define CARRIER_API        __attribute__((visibility("default")))
    #endif
  #else
    #if defined(_WIN32) || defined(_WIN64)
      #define CARRIER_API        __declspec(dllimport)
    #else
      #define CARRIER_API        __attribute__((visibility("default")))
    #endif
  #endif
#else
  #define CARRIER_API
#endif

/**
 * \~English
 * Carrier User address max length.
 */
#define CARRIER_MAX_ADDRESS_LEN             52

/**
 * \~English
 * Carrier Node/User ID max length.
 */
#define CARRIER_MAX_ID_LEN                  45

/**
 * \~English
 * Carrier user name max length.
 */
#define CARRIER_MAX_USER_NAME_LEN           63

/**
 * \~English
 * Carrier user description max length.
 */
#define CARRIER_MAX_USER_DESCRIPTION_LEN    127

/**
 * \~English
 * Carrier user phone number max length.
 */
#define CARRIER_MAX_PHONE_LEN               31

/**
 * \~English
 * Carrier user email address max length.
 */
#define CARRIER_MAX_EMAIL_LEN               127

/**
 * \~English
 * Carrier user region max length.
 */
#define CARRIER_MAX_REGION_LEN              127

/**
 * \~English
 * Carrier user gender max length.
 */
#define CARRIER_MAX_GENDER_LEN              31

/**
 * \~English
 * Carrier node name max length.
 */
#define CARRIER_MAX_NODE_NAME_LEN           63

/**
 * \~English
 * Carrier node description max length.
 */
#define CARRIER_MAX_NODE_DESCRIPTION_LEN    127

/**
 * \~English
 * Carrier App message max length.
 */
#define CARRIER_MAX_APP_MESSAGE_LEN         1024

/**
 * \~English
 * Carrier App max bulk message length.
 */
#define CARRIER_MAX_APP_BULKMSG_LEN        (5 * 1024 * 1024)

/**
 * \~English
 * System reserved reply reason.
 */
#define CARRIER_STATUS_TIMEOUT              1

/**
 * \~English
 * Carrier invite/reply max data length.
 */
#define CARRIER_MAX_INVITE_DATA_LEN         8192

/**
 * \~English
 * Carrier invite/reply max bundle length.
 */
#define CARRIER_MAX_BUNDLE_LEN              511

/**
 * \~English
 * Carrier invite reply max reason length.
 */
#define CARRIER_MAX_INVITE_REPLY_REASON_LEN 255

/**
 * \~English
 * Carrier group title max length.
 */
#define CARRIER_MAX_GROUP_TITLE_LEN         127

/**
 * \~English
 * Carrier representing carrier node singleton instance.
 */
typedef struct Carrier Carrier;

/**
 * \~English
 * Carrier log level to control or filter log output.
 */
typedef enum CarrierLogLevel {
    /**
     * \~English
     * Log level None
     * Indicate disable log output.
     */
    CarrierLogLevel_None = 0,
    /**
     * \~English
     * Log level fatal.
     * Indicate output log with level 'Fatal' only.
     */
    CarrierLogLevel_Fatal = 1,
    /**
     * \~English
     * Log level error.
     * Indicate output log above 'Error' level.
     */
    CarrierLogLevel_Error = 2,
    /**
     * \~English
     * Log level warning.
     * Indicate output log above 'Warning' level.
     */
    CarrierLogLevel_Warning = 3,
    /**
     * \~English
     * Log level info.
     * Indicate output log above 'Info' level.
     */
    CarrierLogLevel_Info = 4,
    /*
     * \~English
     * Log level debug.
     * Indicate output log above 'Debug' level.
     */
    CarrierLogLevel_Debug = 5,
    /*
     * \~English
     * Log level trace.
     * Indicate output log above 'Trace' level.
     */
    CarrierLogLevel_Trace = 6,
    /*
     * \~English
     * Log level verbose.
     * Indicate output log above 'Verbose' level.
     */
    CarrierLogLevel_Verbose = 7
} CarrierLogLevel;

/******************************************************************************
 * Creation & destruction
 *****************************************************************************/

/**
 * \~English
 * Bootstrap defines a couple of perperities to provide for Carrier nodes
 * to connect with. The bootstrap nodes help Carrier nodes be connected to
 * the others with more higher possibilities.
 */
typedef struct BootstrapNode {
    /**
     * \~English
     * The ip address supported with ipv4 protocol.
     */
    const char *ipv4;

    /**
     * \~English
     * The ip address supported with ipv6 protocol.
     */
    const char *ipv6;

    /**
     * \~English
     * The ip port.
     * The default value is 33445.
     */
    const char *port;

    /**
     * \~English
     * The unique public key to provide for Carrier nodes, terminated
     * by null-string.
     * The length of public key is about 45 bytes.
     */
    const char *public_key;
} BootstrapNode;

/**
 * \~English
 * ExpressNode defines a couple of perperities to provide for Carrier node
 * to send offline messages. The definition of ExpressNode is same with
 */
typedef struct ExpressNode {
    /**
     * \~English
     * The ip address supported with ipv4 protocol.
     */
    const char *ipv4;

    /**
     * \~English
     * This field is reserved for future, not suported currently.
     * user should feed this vaue with NULL.
     */
    const char *ipv6;

    /**
     * \~English
     * The ip port.
     * The default value is 33445.
     */
    const char *port;

    /**
     * \~English
     * The unique public key to provide for Carrier nodes, terminated
     * by null-string.
     * The length of public key is about 45 bytes.
     */
    const char *public_key;
} ExpressNode;

/**
 * \~English
 * CarrierOptions defines several settings that control the way the Carrier
 * node connects to others.
 *
 * @remark
 *      Default values are not defined for persistent_location of Carrier-
 *      Options, so application should be set persistent_location clearly.
 *      If the CarrierOptions structure is defined as a static variable,
 *      initialization (in compliant compilers) sets all values to 0 (NULL
 *      for pointers).
 */
typedef struct CarrierOptions {
    /**
     * \~English
     * The application defined persistent data location.
     * The location must be set.
     */
    const char *persistent_location;

    /**
     * \~English
     * The pre-defined secret for the new carrier instance.
     * This field will be ignored when there is persistent data exists.
     *
     * This filed must be 32 bytes long.
     */
    const uint8_t *secret_key;

    /**
     * \~English
     * The option to decide to use udp transport or not. Setting this option
     * to false will force Carrier node to use TCP only, which will potentially
     * slow down the message to run through.
     */
    bool udp_enabled;

    /**
     * \~English
     * Set the log level for Carrier logging output.
     */
    CarrierLogLevel log_level;

    /**
     * \~English
     * Set all logging messages from Carrier output to logfile.
     * Default is NULL, all the logging message will output to stdout.
     */
    char *log_file;

    /**
     * \~English
     * Set a customized log printer, all logging messages from Carrier
     * will also output to this printer.
     * Default is NULL.
     */
    void (*log_printer)(const char *format, va_list args);

    /**
     * \~English
     * The total number of bootstrap nodes to connect.
     * There must have at least one bootstrap node for the very first time
     * to create carrier instance.
     */
    size_t bootstraps_size;

    /**
     * \~English
     * The array of DHT bootstrap nodes.
     */
    BootstrapNode *bootstraps;

    /**
     * \~English
     * The total number of Express nodes to connect.
     * There must have at least on node for the very first time
     * to create carrier instance.
     */
    size_t express_nodes_size;

    /**
     * \~English
     * The array of Express nodes.
     */
    ExpressNode *express_nodes;
} CarrierOptions;

/**
 * \~English
 * Get the current version of Carrier node.
 */
CARRIER_API
const char *carrier_get_version(void);

/**
 * \~English
 * Carrier node connection status to Carrier network.
 */
typedef enum CarrierConnectionStatus {
    /**
     * \~English
     * Carrier node connected to Carrier network.
     * Indicate the Carrier node is online.
     */
    CarrierConnectionStatus_Connected,
    /**
     * \~English
     * There is no connection to Carrier network.
     * Indicate the Carrier node is offline.
     */
    CarrierConnectionStatus_Disconnected,
} CarrierConnectionStatus;

/**
 * \~English
 * Carrier node presence status to Carrier network.
 */
typedef enum CarrierPresenceStatus {
    /**
     * \~English
     * Carrier node is online and available.
     */
    CarrierPresenceStatus_None,
    /**
     * \~English
     * Carrier node is being away.
     * Carrier node can set this value with an user defined inactivity time.
     */
    CarrierPresenceStatus_Away,
    /**
     * \~English
     * Carrier node is being busy.
     * Carrier node can set this value to tell friends that it can not
     * currently wish to commincate.
     */
    CarrierPresenceStatus_Busy,
} CarrierPresenceStatus;

/**
 * \~English
 * A structure representing the Carrier user information.
 *
 * In Carrier SDK, self and all friends are carrier user, and have
 * same user attributes.
 */
typedef struct CarrierUserInfo {
    /**
     * \~English
     * User ID. Read only to application.
     */
    char userid[CARRIER_MAX_ID_LEN+1];
    /**
     * \~English
     * Nickname, also known as display name.
     */
    char name[CARRIER_MAX_USER_NAME_LEN+1];
    /**
     * \~English
     * User's description, also known as what's up.
     */
    char description[CARRIER_MAX_USER_DESCRIPTION_LEN+1];
    /**
     * \~English
     * If user has an avatar.
     */
    int has_avatar;
    /**
     * \~English
     * User's gender.
     */
    char gender[CARRIER_MAX_GENDER_LEN+1];
    /**
     * \~English
     * User's phone number.
     */
    char phone[CARRIER_MAX_PHONE_LEN+1];
    /**
     * \~English
     * User's email address.
     */
    char email[CARRIER_MAX_EMAIL_LEN+1];
    /**
     * \~English
     * User's region information.
     */
    char region[CARRIER_MAX_REGION_LEN+1];
} CarrierUserInfo;

/**
 * \~English
 * A structure representing the Carrier friend information.
 *
 * Include the basic user information and the extra friend information.
 */
typedef struct CarrierFriendInfo {
    /**
     * \~English
     * Friend's user information.
     */
    CarrierUserInfo user_info;
    /**
     * \~English
     * Your label for the friend.
     */
    char label[CARRIER_MAX_USER_NAME_LEN+1];
    /**
     * \~English
     * Friend's connection status.
     */
    CarrierConnectionStatus status;
    /**
     * \~English
     * Friend's presence status.
     */
    CarrierPresenceStatus presence;
} CarrierFriendInfo;

/**
 * \~English
 * A structure representing the Carrier group peer information.
 *
 * Include the basic peer information.
 */
typedef struct CarrierGroupPeer {
    /**
     * \~English
     * Peer's Carrier user name.
     */
    char name[CARRIER_MAX_USER_NAME_LEN + 1];

    /**
     * \~English
     * Peer's userid.
     */
    char userid[CARRIER_MAX_ID_LEN + 1];
} CarrierGroupPeer;

/**
 * \~English
 * Carrier group callbacks, include all global group callbacks for Carrier.
 */
typedef struct CarrierGroupCallbacks {
    /**
     * \~English
     * An application-defined function that process event to be connected to
     * group.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      groupid     [in] The target group connected.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*group_connected)(Carrier *carrier, const char *groupid, void *context);

    /**
     * \~English
     * An application-defined function that process the group messages.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      groupid     [in] The group that received message.
     * @param
     *      from        [in] The user id who send the message.
     * @param
     *      message     [in] The message content.
     * @param
     *      length      [in] The message length in bytes.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*group_message)(Carrier *carrier, const char *groupid,
                          const char *from, const void *message, size_t length,
                          void *context);

    /**
     * \~English
     * An application-defined function that process the group title change
     * event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      groupid     [in] The group id of its title changed.
     * @param
     *      from        [in] The peer Id who changed title name.
     * @param
     *      title       [in] The updated title name.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*group_title)(Carrier *carrier, const char *groupid,
                        const char *from, const char *title, void *context);

    /**
     * \~English
     * An application-defined function that process the group peer's name
     * change event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      groupid     [in] The target group.
     * @param
     *      peerid      [in] The peer Id who changed its name.
     * @param
     *      peer_name   [in] The updated peer name.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*peer_name)(Carrier *carrier, const char *groupid,
                      const char *peerid, const char *peer_name,
                      void *context);

    /**
     * \~English
     * An application-defined function that process the group list change
     * event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      groupid     [in] The target group that changed it's peer list.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*peer_list_changed)(Carrier *carrier, const char *groupid,
                              void *context);
} CarrierGroupCallbacks;

/**
 * \~English
 * Carrier callbacks, include all global callbacks for Carrier.
 */
typedef struct CarrierCallbacks {
    /**
     * \~English
     * An application-defined function that perform idle work.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*idle)(Carrier *carrier, void *context);

    /**
     * \~English
     * An application-defined function that process the self connection status.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      status      [in] Current connection status. @see CarrierConnectionStatus.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*connection_status)(Carrier *carrier,
                              CarrierConnectionStatus status, void *context);

    /**
     * \~English
     * An application-defined function that process the ready notification.
     * Notice: application should wait this callback invoked before calling any
     * carrier function to interact with friends.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*ready)(Carrier *carrier, void *context);

    /**
     * \~English
     * An application-defined function that process the self info change event.
     * This callback is reserved for future compatibility.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      info        [in] The CarrierUserInfo pointer to the new user info.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*self_info)(Carrier *carrier, const CarrierUserInfo *info, void *context);

    /**
     * \~English
     * An application-defined function that iterate the each friends list item.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      info        [in] A pointer to CarrierFriendInfo structure that
     *                       representing a friend(NULL indicates
     *                       iteration finished).
     * @param
     *      context     [in] The application defined context data.
     *
     * @return
     *      Return true to continue iterate next friend user info,
     *      false to stop iterate.
     */
    bool (*friend_list)(Carrier *carrier, const CarrierFriendInfo* info,
                        void* context);

    /**
     * \~English
     * An application-defined function that process the friend connection
     * change event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      status      [in] Connection status. @see CarrierConnectionStatus
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_connection)(Carrier *carrier,const char *friendid,
                              CarrierConnectionStatus status, void *context);

    /**
     * \~English
     * An application-defined function that process the friend information
     * change event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      info        [in] The CarrierFriendInfo pointer to the new friend info.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_info)(Carrier *carrier, const char *friendid,
                        const CarrierFriendInfo *info, void *context);

    /**
     * \~English
     * An application-defined function that process the friend presence
     * change event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      presence    [in] The presence status of the friend.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_presence)(Carrier *carrier, const char *friendid,
                            CarrierPresenceStatus presence, void *context);

    /**
     * \~English
     * An application-defined function that process the friend request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      userid      [in] The user id who wants friend with us.
     * @param
     *      info        [in] The basic user info who wants to be friend.
     * @param
     *      hello       [in] PIN for target user, or any application defined
     *                       content.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_request)(Carrier *carrier, const char *userid,
                           const CarrierUserInfo *info,
                           const char *hello, void *context);

    /**
     * \~English
     * An application-defined function that process the new friend added
     * event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      info        [in] The firend's information.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_added)(Carrier *carrier, const CarrierFriendInfo *info,
                         void *context);

    /**
     * \~English
     * An application-defined function that process the friend removed
     * event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_removed)(Carrier *carrier, const char *friendid,
                           void *context);

    /**
     * \~English
     * An application-defined function that process the friend messages.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      from        [in] The user id from who send the message.
     * @param
     *      msg         [in] The message content.
     * @param
     *      len         [in] The message length in bytes.
     * @param
     *      timestamp   [in] The message sent time as the number of seconds
     *                       since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).
     * @param
     *      offline     [in] The value tells whether this message is received
     *                       as offline message or online message. The value of
     *                       true means this message is received as offline
     *                       message, otherwise as online message.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_message)(Carrier *carrier, const char *from,
                           const void *msg, size_t len,
                           int64_t timestamp, bool offline,
                           void *context);

    /**
     * \~English
     * An application-defined function that process the friend invite request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      from        [in] The user id from who send the invite request.
     * @param
     *      bundle      [in] The bundle attached to this invite request.
     * @param
     *      data        [in] The application defined data send from friend.
     * @param
     *      len         [in] The data length in bytes.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_invite)(Carrier *carrier, const char *from,
                          const char *bundle,
                          const void *data, size_t len, void *context);

    /**
     * \~English
     * An application-defined function that process the group invite request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      from        [in] The user id from who send the invite request.
     * @param
     *      cookie      [in] The application defined cookie send from friend.
     * @param
     *      len         [in] The data length in bytes.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*group_invite)(Carrier *w, const char *from,
                         const void *cookie, size_t len, void *context);

    /**
     * \~English
     * Group related callbacks.
     */
    CarrierGroupCallbacks group_callbacks;
} CarrierCallbacks;

/**
 * \~English
 * Check if the carrier address is valid.
 *
 * @param
 *      address     [in] the carrier address to be check.
 *
 * @return
 *      true if address is valid, or false if address is not valid.
 */
CARRIER_API
bool carrier_address_is_valid(const char *address);

/**
 * \~English
 * Check if the carrier ID is valid.
 *
 * @param
 *      id          [in] the carrier id to be check.
 *
 * @return
 *      true if id is valid, or false if id is not valid.
 */
CARRIER_API
bool carrier_id_is_valid(const char *id);

/**
 * \~English
 * Extract carrier userid (or nodeid) from the carrier address.
 *
 * @param
 *      address     [in] the carrier address to be check.
 * @param
 *      userid      [in] the buffer to save the extracted userid.
 * @param
 *      len         [in] the length of buffer.
 *
 * @return
 *      If no error occurs, return the pointer of extraced userid.
 *      Otherwise, return NULL, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
CARRIER_API
char *carrier_get_id_by_address(const char *address, char *userid, size_t len);

/**
 * \~English
 * Create a new Carrier node instance. after creating the instance, it's
 * ready for connection to Carrier network.
 *
 * @param
 *      options     [in] A pointer to a valid CarrierOptions structure.
 * @param
 *      callbacks   [in] The Application defined callback functions.
 * @param
 *      context     [in] The application defined context data.
 *
 * @return
 *      If no error occurs, return the pointer of Carrier node instance.
 *      Otherwise, return NULL, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
CARRIER_API
Carrier *carrier_new(const CarrierOptions *options, CarrierCallbacks *callbacks,
                    void *context);

/**
 * \~English
 * Disconnect from Carrier network, and destroy all associated resources
 * with the Carrier node instance.
 *
 * After calling the function, the Carrier pointer becomes invalid.
 * No other functions can be called.
 *
 * @param
 *      carrier     [in] A handle identifying the Carrier node instance
 *                       to kill.
 */
CARRIER_API
void carrier_kill(Carrier *carrier);

/******************************************************************************
 * \~English
 * Connection & event loop
 *****************************************************************************/
/**
 * \~English
 * Attempts to connect the node to Carrier network. If the node successfully
 * connects to Carrier network, then it starts the node's main event loop.
 * The connect options was specified by previously create options.
 * @see carrier_new().
 *
 * @param
 *      carrier     [in] A handle identifying the Carrier node instance.
 * @param
 *      interval    [in] Internal loop interval, in milliseconds.
 *
 * @return
 *      0 if the client successfully connected to Carrier network and start the
 *      event loop. Otherwise, return -1, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_run(Carrier *carrier, int interval);

/******************************************************************************
 * Internal node information
 *****************************************************************************/

/**
 * \~English
 * Get user address associated with the Carrier node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      address     [out] The buffer that will receive the address.
 *                        The buffer size should at least
 *                        (CARRIER_MAX_ADDRESS_LEN + 1) bytes.
 * @param
 *      len         [in] The buffer size of address.
 *
 * @return
 *      The address string pointer, or NULL if buffer is too small.
 */
CARRIER_API
char *carrier_get_address(Carrier *carrier, char *address, size_t len);

/**
 * \~English
 * Get node identifier associated with this Carrier node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      nodeid      [out] The buffer that will receive the identifier.
 *                        The buffer size should at least
 *                        (CARRIER_MAX_ID_LEN + 1) bytes.
 * @param
 *      len         [in] The buffer size of nodeid.
 *
 * @return
 *      The nodeId string pointer, or NULL if buffer is too small.
 */
CARRIER_API
char *carrier_get_nodeid(Carrier *carrier, char *nodeid, size_t len);

/**
 * \~English
 * Get user identifier associated with this Carrier node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [out] The buffer that will receive the identifier.
 *                        The buffer size should at least
 *                        (CARRIER_MAX_ID_LEN + 1) bytes.
 * @param
 *      len         [in] The buffer size of userid.
 *
 * @return
 *      The userId string pointer, or NULL if buffer is too small.
 */
CARRIER_API
char *carrier_get_userid(Carrier *carrier, char *userid, size_t len);

/******************************************************************************
 * Client information
 *****************************************************************************/

/**
 * \~Egnlish
 * Update the nospam for Carrier address.
 *
 * Update the 4-byte nospam part of the Carrier address with host byte order
 * expected. Nospam for Carrier address is used to eliminate spam friend
 * request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      nospam      [in] An 4-bytes unsigned integer.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_set_self_nospam(Carrier *carrier, uint32_t nospam);

/**
 * \~Egnlish
 * Get the nospam for Carrier address.
 *
 * Get the 4-byte nospam part of the Carrier address with host byte order
 * expected. Nospam for Carrier address is used to eliminate spam friend
 * request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      nospam      [in] An unsigned integer pointer to receive nospam value.
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_get_self_nospam(Carrier *carrier, uint32_t *nospam);

/**
 * \~English
 * Update self information.
 *
 * As self information changed, Carrier node would update itself information
 * to Carrier network, which would forward the change to all friends.
 * nodes.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      info        [in] The CarrierUserInfo pointer to the updated user info.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_set_self_info(Carrier *carrier, const CarrierUserInfo *info);

/**
 * \~English
 * Get self information.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      info        [in] The CarrierUserInfo pointer to receive user info.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_get_self_info(Carrier *carrier, CarrierUserInfo *info);

/**
 * \~English
 * Set self presence status.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      presence    [in] the new presence status.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_set_self_presence(Carrier *carrier, CarrierPresenceStatus presence);

/**
 * \~English
 * Get self presence status.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      presence    [in] A pointer to receive presence status value.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_get_self_presence(Carrier *carrier, CarrierPresenceStatus *presence);

/**
 * \~English
 * Check if Carrier node instance is being ready.
 *
 * All carrier interactive APIs should be called only if carrier instance
 * is being ready.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 *
 * @return
 *      true if the carrier node instance is ready, or false if not.
 */
CARRIER_API
bool carrier_is_ready(Carrier *carrier);

/******************************************************************************
 * Friend information
 *****************************************************************************/

/**
 * \~English
 * An application-defined function that iterate the each friends list item.
 *
 * CarrierFriendsIterateCallback is the callback function type.
 *
 * @param
 *      info        [in] A pointer to CarrierFriendInfo structure that
 *                       representing a friend(NULL indicates
 *                       iteration finished).
 * @param
 *      context     [in] The application defined context data.
 *
 * @return
 *      Return true to continue iterate next friend user info,
 *      false to stop iterate.
 */
typedef bool CarrierFriendsIterateCallback(const CarrierFriendInfo *info,
                                           void *context);
/**
 * \~English
 * Get friends list. For each friend will call the application defined
 * iterate callback.
 *
 * @param
 *      carrier     [in] a handle to the Carrier node instance.
 * @param
 *      callback    [in] a pointer to CarrierFriendsIterateCallback function.
 * @param
 *      context     [in] the application defined context data.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_get_friends(Carrier *carrier,
                        CarrierFriendsIterateCallback *callback, void *context);

/**
 * \~English
 * Get friend information.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      friendid    [in] The friend's user id.
 * @param
 *      info        [in] The CarrierFriendInfo pointer to receive the friend
 *                       information.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_get_friend_info(Carrier *carrier, const char *friendid,
                            CarrierFriendInfo *info);

/**
 * \~English
 * Set the label of the specified friend.
 *
 * If the value length is 0 or value is NULL, the attribute will be cleared.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      friendid    [in] The friend's user id.
 * @param
 *      label       [in] the new label of the specified friend.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 *
 * @remarks
 *      The label of a friend is a private alias named by yourself. It can be
 *      seen by yourself only, and has no impact to the target friend.
 */
CARRIER_API
int carrier_set_friend_label(Carrier *carrier,
                             const char *friendid, const char *label);

/**
 * \~English
 * Check if the user ID is friend.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [in] The userid to check.
 *
 * @return
 *      true if the user id is friend, or false if not;
 */
CARRIER_API
bool carrier_is_friend(Carrier* carrier, const char* userid);

/******************************************************************************
 * Friend add & remove
 *****************************************************************************/

/**
 * \~English
 * Attempt to add friend by sending a new friend request.
 *
 * This function will add a new friend with specific address, and then
 * send a friend request to the target node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      address     [in] The target user address.
 * @param
 *      hello       [in] PIN for target user, or any application defined
 *                       content.
 *
 * @return
 *      0 if adding friend is successful. Otherwise, return -1, and a specific
 *      error code can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_add_friend(Carrier *carrier, const char *address, const char *hello);

/**
 * \~English
 * Accept the friend request.
 *
 * This function is used to add a friend in response to a friend request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [in] The user id to who wants to be friend with us.
 *
 * @return
 *      0 if adding friend successfully.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_accept_friend(Carrier *carrier, const char *userid);

/**
 * \~English
 * Remove a friend.
 *
 * This function will send a remove friend indicator to Carrier network.
 *
 * If all correct, Carrier network will clean the friend relationship, and
 * send friend removed message to both.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [in] The target user id.
 *
 * @return
 *      0 if the indicator successfully sent.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_remove_friend(Carrier *carrier, const char *userid);

/******************************************************************************
 * Application transactions between friends
 *****************************************************************************/

/**
 * \~English
 * Carrier message receipt status to Carrier network.
 */
typedef enum CarrierReceiptState {
    /**
     * \~English
     * Message has been accepted by remote friend via carrier network.
     */
    CarrierReceipt_ByFriend,
    /**
     * \~English
     * Message has been delivered to offline message store.
     */
    CarrierReceipt_Offline,
    /**
     * \~English
     * Message sent before not
     * Message send unsuccessfully. A specific error code can be
     * retrieved by calling carrier_get_error().
     */
    CarrierReceipt_Error,
} CarrierReceiptState;

/**
 * \~English
 * An application-defined function that notify the message receipt status.
 *
 * CarrierFriendMessageReceiptCallback is the callback function type.
 *
 * @param
 *      msgid        [in] The unique id.
 * @param
 *      state        [in] The message sent state.
 * @param
 *      context      [in] The application defined context data.
 *
 * @return
 *      Return true to continue iterate next friend user info,
 *      false to stop iterate.
 */
typedef void CarrierFriendMessageReceiptCallback(uint32_t msgid,
                                             CarrierReceiptState state,
                                             void *context);

/**
 * \~English
 * Send a message to a friend with receipt.
 *
 * The message length may not exceed CARRIER_MAX_BULK_MESSAGE_LEN. Larger messages
 * must be split by application and sent as separate fragments. Other carrier
 * nodes can reassemble the fragments.
 *
 * Message may not be empty or NULL.
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      to          [in] The target userid.
 * @param
 *      message     [in] The message content defined by application.
 * @param
 *      len         [in] The message length in bytes.
 * @param
 *      msgid       [out] The message ID.
 * @param
 *      cb          [in] The pointer to callback which will be called when the
 *                        receipt is received or failed to send message.
 * @param
 *      content     [in] The user context in callback.
 *
 * @return
 *      0 if the text message successfully sent.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
 CARRIER_API
int carrier_send_friend_message(Carrier *carrier, const char *to,
                            const void *message, size_t len,
                            uint32_t *msgid,
                            CarrierFriendMessageReceiptCallback *cb, void *context);

/**
 * \~English
 * An application-defined function that process the friend invite response.
 *
 * CarrierFriendInviteResponseCallback is the callback function type.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      from        [in] The target user id.
 * @param
 *      bundle      [in] The bundle attached to this invite reply.
 * @param
 *      status      [in] The status code of the response.
 *                       0 is success, otherwise is error.
 * @param
 *      reason      [in] The error message if status is error, or NULL
 * @param
 *      data        [in] The application defined data return by target user.
 * @param
 *      len         [in] The data length in bytes.
 * @param
 *      context      [in] The application defined context data.
 */
typedef void CarrierFriendInviteResponseCallback(Carrier *carrier,
                                             const char *from,
                                             const char *bundle,
                                             int status, const char *reason,
                                             const void *data, size_t len,
                                             void *context);

/**
 * \~English
 * Send invite request to a friend.
 *
 * Application can attach the application defined data within the invite
 * request, and the data will send to target friend.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      to          [in] The target userid.
 * @param
 *      bundle      [in] The bundle attached to this invitation.
 * @param
 *      data        [in] The application defined data send to target user.
 * @param
 *      len         [in] The data length in bytes.
 * @param
 *      callback    [in] A pointer to CarrierFriendInviteResponseCallback
 *                       function to receive the invite response.
 * @param
 *      context      [in] The application defined context data.
 *
 * @return
 *      0 if the invite request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_invite_friend(Carrier *carrier, const char *to, const char *bundle,
                          const void *data, size_t len,
                          CarrierFriendInviteResponseCallback *callback,
                          void *context);

/**
 * \~English
 * Reply the friend invite request.
 *
 * This function will send a invite response to friend.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      to          [in] The userid who send invite request.
 * @param
 *      bundle      [in] The bundle attached to this invitation reply.
 * @param
 *      status      [in] The status code of the response.
 *                       0 is success, otherwise is error.
 * @param
 *      reason      [in] The error message if status is error, or NULL
 *                       if success.
 * @param
 *      data        [in] The application defined data send to target user.
 *                       If the status is error, this will be ignored.
 * @param
 *      len         [in] The data length in bytes.
 *                       If the status is error, this will be ignored.
 *
 * @return
 *      0 if the invite response successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_reply_friend_invite(Carrier *carrier, const char *to,
                                const char *bundle,
                                int status, const char *reason,
                                const void *data, size_t len);

/******************************************************************************
 * Group lifecycle and messaging.
 *****************************************************************************/
/**
 * \~English
 * Create a new group
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      groupid     [out] The buffer to receive a created group Id.
 * @param
 *      length      [in] The buffer length to receive the group Id.
 *
 * @return
 *      0 if creating group in success, Otherwise, return -1, and a specific
 *      error code can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_new_group(Carrier *carrier, char *groupid, size_t length);

/**
 * \~English
 * Leave from a specified group
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      groupid     [in] The group to leave from.
 *
 * @return
 *      0 if leaving from group in success, Otherwise, return -1, and a specific
 *      error code can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_leave_group(Carrier *carrier, const char *groupid);

/**
 * \~English
 * Invite a specified friend into group.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      groupid     [in] The group into which we intend to invite friend.
 * @param
 *      friendid    [in] The friend that we intend to invite.
 *
 * @return
 *      0 on success, or -1 if an error occurred, and a specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_group_invite(Carrier *carrier, const char *groupid, const char *friendid);

/**
 * \~English
 * Join a specified group with cookie invited from remote friend.
 *
 * This function should be called only if application received a group
 * invitation from remote friend.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      friendid    [in] The friend who send a group invitation.
 * @param
 *      cookie      [in] The cookie information required to join group.
 * @param
 *      cookie_len  [in] The buffer length to cookie.
 * @param
 *      groupId     [out] The buffer to receive group id.
 * @param
 *      group_len   [in] The buffer length to receive group Id.
 *
 * @return
 *      0 on success, or -1 if an error occurred, and a specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_group_join(Carrier *carrier, const char *friendid, const void *cookie,
                   size_t cookie_len, char *groupId, size_t group_len);

/**
 * \~English
 * Send a message to a group.
 *
 * The message length may not exceed CARRIER_MAX_APP_MESSAGE_LEN. Larger messages
 * must be split by application and sent as separate fragments. Other carrier
 * nodes can reassemble the fragments.
 *
 * Message may not be empty or NULL.
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      groupid     [in] The target group to send message.
 * @param
 *      message     [in] The message content defined by application.
 * @param
 *      length      [in] The message length in bytes.
 *
 * @return
 *      0 on success, or -1 if an error occurred, and a specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_group_send_message(Carrier *carrier, const char *groupid,
                               const void *message, size_t length);

/**
 * \~English
 * Get group title.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      groupid     [in] The target group.
 * @param
 *      title       [out] The buffer to receive group title.
 * @param
 *      length      [in] The length of buffer to receive group title.
 *
 * @return
 *      0 on success, or -1 if an error occurred, and a specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_group_get_title(Carrier *carrier, const char *groupid, char *title,
                            size_t length);

/**
 * \~English
 * Set group title.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      groupid     [in] The target group.
 * @param
 *      title       [in] The title name to set(should be no
 *                       longer than CARRIER_MAX_GROUP_TITLE_LEN).
 *
 * @return
 *      0 on success, or -1 if an error occurred, and a specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_group_set_title(Carrier *carrier, const char *groupid, const char *title);

/**
 * \~English
 * An application-defined function that iterate the each peers list item
 * of a specified group.
 *
 * CarrierGroupPeersIterateCallback is the callback function type.
 *
 * @param
 *      peer        [in] A pointer to CarrierGroupPeer structure that
 *                       representing a group peer(NULL indicates
 *                       iteration finished).
 * @param
 *      context     [in] The application defined context data.
 *
 * @return
 *      Return true to continue iterate next group peer, false to stop
 *      iteration.
 */
typedef bool CarrierGroupPeersIterateCallback(const CarrierGroupPeer *peer,
                                              void *context);
/**
 * \~English
 * Get group peer list. For each peer will call the application defined
 * iterate callback.
 *
 * @param
 *      carrier     [in] a handle to the Carrier node instance.
 * @param
 *      groupid     [in] The target group.
 * @param
 *      callback    [in] a pointer to CarrierGroupPeersIterateCallback function.
 * @param
 *      context     [in] the application defined context data.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_group_get_peers(Carrier *carrier, const char *groupid,
                            CarrierGroupPeersIterateCallback *callback,
                            void *context);

/**
 * \~English
 * Get group peer information.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      groupid     [in] The target group.
 * @param
 *      peerId      [in] The target peerId to get it's information.
 * @param
 *      peer        [in] The CarrierGroupPeer pointer to receive the peer
 *                       information.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_group_get_peer(Carrier *carrier, const char *groupid,
                           const char *peerId, CarrierGroupPeer *peer);

/**
 * \~English
 * An application-defined function that iterate the each group.
 *
 * CarrierIterateGroupCallback is the callback function type.
 *
 * @param
 *      groupid     [in] A pointer to iterating group Id(NULL
 *                       indicates iteration finished).
 * @param
 *      context     [in] The application defined context data.
 *
 * @return
 *      Return true to continue iterate next group peer, false to stop
 *      iteration.
 */
typedef bool CarrierIterateGroupCallback(const char *groupid, void *context);

/**
 * \~English
 * Get group list. For each group will call the application defined
 * iterate callback.
 *
 * @param
 *      carrier     [in] a handle to the Carrier node instance.
 * @param
 *      callback    [in] a pointer to CarrierIterateGroupCallback function.
 * @param
 *      context     [in] the application defined context data.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling carrier_get_error().
 */
CARRIER_API
int carrier_get_groups(Carrier *carrier, CarrierIterateGroupCallback *callback,
                       void *context);

/******************************************************************************
 * Error handling
 *****************************************************************************/

#define CARRIER_SUCCESS                                  0

// Facility code
#define FACILITY_GENERAL                                0x01
#define FACILITY_SYS                                    0x02
#define FACILITY_RESERVED1                              0x03
#define FACILITY_RESERVED2                              0x04
#define FACILITY_ICE                                    0x05
#define FACILITY_DHT                                    0x06
#define FACILITY_EXPRESS                                0x07

/**
 * \~English
 * Argument(s) is(are) invalid.
 */
#define ERROR_INVALID_ARGS                         0x01

/**
 * \~English
 * Runs out of memory.
 */
#define ERROR_OUT_OF_MEMORY                        0x02

/**
 * \~English
 * Buffer size is too small.
 */
#define ERROR_BUFFER_TOO_SMALL                     0x03

/**
 * \~English
 * Persistent data is corrupted.
 */
#define ERROR_BAD_PERSISTENT_DATA                  0x04

/**
 * \~English
 * Persistent file is invalid.
 */
#define ERROR_INVALID_PERSISTENCE_FILE             0x05

/**
 * \~English
 * Control packet is invalid.
 */
#define ERROR_INVALID_CONTROL_PACKET               0x06

/**
 * \~English
 * Credential is invalid.
 */
#define ERROR_INVALID_CREDENTIAL                   0x07

/**
 * \~English
 * Carrier ran already.
 */
#define ERROR_ALREADY_RUN                          0x08

/**
 * \~English
 * Carrier not ready.
 */
#define ERROR_NOT_BEING_READY                      0x09

/**
 * \~English
 * The requested entity does not exist.
 */
#define ERROR_NOT_EXIST                            0x0A

/**
 * \~English
 * The entity exists already.
 */
#define ERROR_ALREADY_EXIST                        0x0B

/**
 * \~English
 * There are no matched requests.
 */
#define ERROR_NO_MATCHED_REQUEST                   0x0C

/**
 * \~English
 * User ID is invalid.
 */
#define ERROR_INVALID_USERID                       0x0D

/**
 * \~English
 * Node ID is invalid.
 */
#define ERROR_INVALID_NODEID                       0x0E

/**
 * \~English
 * Failed because wrong state.
 */
#define ERROR_WRONG_STATE                          0x0F

/**
 * \~English
 * Stream busy.
 */
#define ERROR_BEING_BUSY                           0x10

/**
 * \~English
 * Language binding error.
 */
#define ERROR_LANGUAGE_BINDING                     0x11

/**
 * \~English
 * Encryption failed.
 */
#define ERROR_ENCRYPT                              0x12

/**
 * \~English
 * The content size of SDP is too long.
 */
#define ERROR_SDP_TOO_LONG                         0x13

/**
 * \~English
 * Bad SDP information format.
 */
#define ERROR_INVALID_SDP                          0x14

/**
 * \~English
 * Not implemented yet.
 */
#define ERROR_NOT_IMPLEMENTED                      0x15

/**
 * \~English
 * Limits are exceeded.
 */
#define ERROR_LIMIT_EXCEEDED                       0x16

/**
 * \~English
 * Allocate port unsuccessfully.
 */
#define ERROR_PORT_ALLOC                           0x17

/**
 * \~English
 * Invalid proxy type.
 */
#define ERROR_BAD_PROXY_TYPE                       0x18

/**
 * \~English
 * Invalid proxy host.
 */
#define ERROR_BAD_PROXY_HOST                       0x19

/**
 * \~English
 * Invalid proxy port.
 */
#define ERROR_BAD_PROXY_PORT                       0x1A

/**
 * \~English
 * Proxy is not available.
 */
#define ERROR_PROXY_NOT_AVAILABLE                  0x1B

/**
 * \~English
 * Persistent data is encrypted, load failed.
 */
#define ERROR_ENCRYPTED_PERSISTENT_DATA            0x1C

/**
 * \~English
 * Invalid bootstrap host.
 */
#define ERROR_BAD_BOOTSTRAP_HOST                   0x1D

/**
 * \~English
 * Invalid bootstrap port.
 */
#define ERROR_BAD_BOOTSTRAP_PORT                   0x1E

/**
 * \~English
 * Data is too long.
 */
#define ERROR_TOO_LONG                             0x1F

/**
 * \~English
 * Could not friend yourself.
 */
#define ERROR_ADD_SELF                             0x20

/**
 * \~English
 * Invalid address.
 */
#define ERROR_BAD_ADDRESS                          0x21

/**
 * \~English
 * Friend is offline.
 */
#define ERROR_FRIEND_OFFLINE                       0x22

/**
 * \~English
 * Bad flat buffer.
 */
#define ERROR_BAD_FLATBUFFER                       0x23

/**
 * \~English
 * Unknown error.
 */
#define ERROR_UNKNOWN                              0xFF

#define CARRIER_MK_ERROR(facility, code)  (0x80000000 | ((facility) << 24) | \
                        ((((code) & 0x80000000) >> 8) | ((code) & 0x7FFFFFFF)))

#define CARRIER_GENERAL_ERROR(code)       CARRIER_MK_ERROR(FACILITY_GENERAL, code)
#define CARRIER_SYS_ERROR(code)           CARRIER_MK_ERROR(FACILITY_SYS, code)
#define CARRIER_ICE_ERROR(code)           CARRIER_MK_ERROR(FACILITY_ICE, code)
#define CARRIER_DHT_ERROR(code)           CARRIER_MK_ERROR(FACILITY_DHT, code)
#define CARRIER_EXPRESS_ERROR(code)       CARRIER_MK_ERROR(FACILITY_EXPRESS, code)

/*
 * \~English
 * Retrieves the last-error code value. The last-error code is maintained on a
 * per-instance basis. Multiple instance do not overwrite each other's
 * last-error code.
 *
 * @return
 *      The return value is the last-error code.
 */
CARRIER_API
int carrier_get_error(void);

/**
 * \~English
 * Clear the last-error code of a Carrier instance.
 */
CARRIER_API
void carrier_clear_error(void);

/**
 * \~English
 * Get string description to error code.
 */
CARRIER_API
char *carrier_get_strerror(int errnum, char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#include <carrier_deprecated.h>

#if defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif /* __ELASTOS_CARRIER_H__ */
