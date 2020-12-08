Elastos Carrier error number
============================

Error number format
-------------------

The Carrier error numbering space is extensible. The numbering space has the following internal structure.

+----------+-----------+--------+
|     0    |   1 ~ 7   | 8 ~ 31 |
+==========+===========+========+
| Severity | Facility  |  Code  |
+----------+-----------+--------+

An error number value has 32 bits divided into three fields: a severity code, a facility code, and an error code. The severity code indicates whether the return value represents information, warning, or error. The facility code identifies the area of the system responsible for the error. The error code is a unique number that is assigned to represent the exception.

Format details
##############

* Severity - indicates a error

  - 1 - Failure

* Facility - indicates the Carrier module that is responsible for the error. Available facility codes are shown below:

  - 1 - General
  - 2 - System
  - 3 - HTTP
  - 4 - Reserved/not used
  - 5 - ICE
  - 6 - DHT

* Code - is the facility's error code

Example
#######

0x86000021

* 0x8 - Error
* 0x6 - DHT
* 0x21 - The error number(ERROR_BAD_BOOTSTRAP_PORT)

Error codes
-----------

ERROR_INVALID_ARGS
##################

.. doxygendefine:: ERROR_INVALID_ARGS
   :project: CarrierAPI


ERROR_OUT_OF_MEMORY
###################

.. doxygendefine:: ERROR_OUT_OF_MEMORY
   :project: CarrierAPI

ERROR_BUFFER_TOO_SMALL
######################

.. doxygendefine:: ERROR_BUFFER_TOO_SMALL
   :project: CarrierAPI

ERROR_BAD_PERSISTENT_DATA
#########################

.. doxygendefine:: ERROR_BAD_PERSISTENT_DATA
   :project: CarrierAPI

ERROR_INVALID_PERSISTENCE_FILE
##############################

.. doxygendefine:: ERROR_INVALID_PERSISTENCE_FILE
   :project: CarrierAPI

ERROR_INVALID_CONTROL_PACKET
############################

.. doxygendefine:: ERROR_INVALID_CONTROL_PACKET
   :project: CarrierAPI

ERROR_INVALID_CREDENTIAL
########################

.. doxygendefine:: ERROR_INVALID_CREDENTIAL
   :project: CarrierAPI

ERROR_ALREADY_RUN
#################

.. doxygendefine:: ERROR_ALREADY_RUN
   :project: CarrierAPI

ERROR_NOT_READY
###############

.. doxygendefine:: ERROR_NOT_READY
   :project: CarrierAPI

ERROR_NOT_EXIST
###############

.. doxygendefine:: ERROR_NOT_EXIST
   :project: CarrierAPI

ERROR_ALREADY_EXIST
###################

.. doxygendefine:: ERROR_ALREADY_EXIST
   :project: CarrierAPI

ERROR_NO_MATCHED_REQUEST
########################

.. doxygendefine:: ERROR_NO_MATCHED_REQUEST
   :project: CarrierAPI

ERROR_INVALID_USERID
####################

.. doxygendefine:: ERROR_INVALID_USERID
   :project: CarrierAPI

ERROR_INVALID_NODEID
####################

.. doxygendefine:: ERROR_INVALID_NODEID
   :project: CarrierAPI

ERROR_WRONG_STATE
#################

.. doxygendefine:: ERROR_WRONG_STATE
   :project: CarrierAPI

ERROR_BEING_BUSY
################

.. doxygendefine:: ERROR_BEING_BUSY
   :project: CarrierAPI

ERROR_LANGUAGE_BINDING
######################

.. doxygendefine:: ERROR_LANGUAGE_BINDING
   :project: CarrierAPI

ERROR_ENCRYPT
#############

.. doxygendefine:: ERROR_ENCRYPT
   :project: CarrierAPI

ERROR_SDP_TOO_LONG
##################

.. doxygendefine:: ERROR_SDP_TOO_LONG
   :project: CarrierAPI

ERROR_INVALID_SDP
#################

.. doxygendefine:: ERROR_INVALID_SDP
   :project: CarrierAPI

ERROR_NOT_IMPLEMENTED
#####################

.. doxygendefine:: ERROR_NOT_IMPLEMENTED
   :project: CarrierAPI

ERROR_LIMIT_EXCEEDED
####################

.. doxygendefine:: ERROR_LIMIT_EXCEEDED
   :project: CarrierAPI

ERROR_PORT_ALLOC
################

.. doxygendefine:: ERROR_PORT_ALLOC
   :project: CarrierAPI

ERROR_BAD_PROXY_TYPE
####################

.. doxygendefine:: ERROR_BAD_PROXY_TYPE
   :project: CarrierAPI

ERROR_BAD_PROXY_HOST
####################

.. doxygendefine:: ERROR_BAD_PROXY_HOST
   :project: CarrierAPI


ERROR_BAD_PROXY_PORT
####################

.. doxygendefine:: ERROR_BAD_PROXY_PORT
   :project: CarrierAPI

ERROR_PROXY_NOT_AVAILABLE
#########################

.. doxygendefine:: ERROR_PROXY_NOT_AVAILABLE
   :project: CarrierAPI

ERROR_ENCRYPTED_PERSISTENT_DATA
###############################

.. doxygendefine:: ERROR_ENCRYPTED_PERSISTENT_DATA
   :project: CarrierAPI

ERROR_BAD_BOOTSTRAP_HOST
########################

.. doxygendefine:: ERROR_BAD_BOOTSTRAP_HOST
   :project: CarrierAPI

ERROR_BAD_BOOTSTRAP_PORT
########################

.. doxygendefine:: ERROR_BAD_BOOTSTRAP_PORT
   :project: CarrierAPI

ERROR_TOO_LONG
##############

.. doxygendefine:: ERROR_TOO_LONG
   :project: CarrierAPI


ERROR_ADD_SELF
##############

.. doxygendefine:: ERROR_ADD_SELF
   :project: CarrierAPI

ERROR_BAD_ADDRESS
#################

.. doxygendefine:: ERROR_BAD_ADDRESS
   :project: CarrierAPI

ERROR_FRIEND_OFFLINE
####################

.. doxygendefine:: ERROR_FRIEND_OFFLINE
   :project: CarrierAPI

ERROR_UNKNOWN
#############

.. doxygendefine:: ERROR_UNKNOWN
   :project: CarrierAPI
