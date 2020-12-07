Elastos Carrier core APIs
=========================

Constants
---------

CARRIER_MAX_ADDRESS_LEN
#######################

.. doxygendefine:: CARRIER_MAX_ADDRESS_LEN
   :project: CarrierAPI

CARRIER_MAX_ID_LEN
##################

.. doxygendefine:: CARRIER_MAX_ID_LEN
   :project: CarrierAPI

CARRIER_MAX_USER_NAME_LEN
#########################

.. doxygendefine:: CARRIER_MAX_USER_NAME_LEN
   :project: CarrierAPI

CARRIER_MAX_USER_DESCRIPTION_LEN
################################

.. doxygendefine:: CARRIER_MAX_USER_DESCRIPTION_LEN
   :project: CarrierAPI

CARRIER_MAX_PHONE_LEN
#####################

.. doxygendefine:: CARRIER_MAX_PHONE_LEN
   :project: CarrierAPI

CARRIER_MAX_EMAIL_LEN
#####################

.. doxygendefine:: CARRIER_MAX_EMAIL_LEN
   :project: CarrierAPI

CARRIER_MAX_REGION_LEN
######################

.. doxygendefine:: CARRIER_MAX_REGION_LEN
   :project: CarrierAPI

CARRIER_MAX_GENDER_LEN
######################

.. doxygendefine:: CARRIER_MAX_GENDER_LEN
   :project: CarrierAPI

CARRIER_MAX_NODE_NAME_LEN
#########################

.. doxygendefine:: CARRIER_MAX_NODE_NAME_LEN
   :project: CarrierAPI

CARRIER_MAX_NODE_DESCRIPTION_LEN
################################

.. doxygendefine:: CARRIER_MAX_NODE_DESCRIPTION_LEN
   :project: CarrierAPI

CARRIER_MAX_APP_MESSAGE_LEN
###########################

.. doxygendefine:: CARRIER_MAX_APP_MESSAGE_LEN
   :project: CarrierAPI

CARRIER_MAX_APP_BULKMSG_LEN
###########################

.. doxygendefine:: CARRIER_MAX_APP_BULKMSG_LEN
   :project: CarrierAPI

Data types
----------

Bootstrap
#########

.. doxygenstruct:: BootstrapNode
   :project: CarrierAPI
   :members:

CarrierOptions
##############

.. doxygenstruct:: CarrierOptions
   :project: CarrierAPI
   :members:


CarrierConnectionStatus
#######################

.. doxygenenum:: CarrierConnectionStatus
   :project: CarrierAPI


CarrierPresenceStatus
#####################

.. doxygenenum:: CarrierPresenceStatus
   :project: CarrierAPI

CarrierLogLevel
###############

.. doxygenenum:: CarrierLogLevel
   :project: CarrierAPI

CarrierUserInfo
###############

.. doxygenstruct:: CarrierUserInfo
   :project: CarrierAPI
   :members:

CarrierFriendInfo
#################

.. doxygenstruct:: CarrierFriendInfo
   :project: CarrierAPI
   :members:

CarrierCallbacks
################

.. doxygenstruct:: CarrierCallbacks
   :project: CarrierAPI
   :members:

CarrierFriendsIterateCallback
#############################

.. doxygentypedef:: CarrierFriendsIterateCallback
   :project: CarrierAPI

CarrierFriendInviteResponseCallback
###################################

.. doxygentypedef:: CarrierFriendInviteResponseCallback
   :project: CarrierAPI

Functions
---------

Carrier instance
################

carrier_new
~~~~~~~~~~~

.. doxygenfunction:: carrier_new
   :project: CarrierAPI

carrier_run
~~~~~~~~~~~

.. doxygenfunction:: carrier_run
   :project: CarrierAPI

carrier_kill
~~~~~~~~~~~~

.. doxygenfunction:: carrier_kill
   :project: CarrierAPI

carrier_is_ready
~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_is_ready
   :project: CarrierAPI

Node Information
################

carrier_get_address
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_address
   :project: CarrierAPI

carrier_get_nodeid
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_nodeid
   :project: CarrierAPI

carrier_get_userid
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_userid
   :project: CarrierAPI

carrier_get_id_by_address
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_id_by_address
   :project: CarrierAPI

carrier_set_self_nospam
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_set_self_nospam
   :project: CarrierAPI

carrier_get_self_nospam
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_self_nospam
   :project: CarrierAPI

carrier_set_self_info
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_set_self_info
   :project: CarrierAPI

carrier_get_self_info
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_self_info
   :project: CarrierAPI

carrier_set_self_presence
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_set_self_presence
   :project: CarrierAPI

carrier_get_self_presence
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_self_presence
   :project: CarrierAPI


Friend & interaction
####################

carrier_get_friends
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_friends
   :project: CarrierAPI

carrier_get_friend_info
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_friend_info
   :project: CarrierAPI

carrier_set_friend_label
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_set_friend_label
   :project: CarrierAPI

carrier_is_friend
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_is_friend
   :project: CarrierAPI

carrier_add_friend
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_add_friend
   :project: CarrierAPI

carrier_accept_friend
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_accept_friend
   :project: CarrierAPI

carrier_remove_friend
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_remove_friend
   :project: CarrierAPI

carrier_send_friend_message
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_send_friend_message
   :project: CarrierAPI

carrier_invite_friend
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_invite_friend
   :project: CarrierAPI

carrier_reply_friend_invite
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_reply_friend_invite
   :project: CarrierAPI


Utility functions
#################

carrier_get_version
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_version
   :project: CarrierAPI

carrier_address_is_valid
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_address_is_valid
   :project: CarrierAPI

carrier_id_is_valid
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_id_is_valid
   :project: CarrierAPI

carrier_get_error
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_get_error
   :project: CarrierAPI

carrier_clear_error
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_clear_error
   :project: CarrierAPI
