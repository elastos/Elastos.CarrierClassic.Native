Elastos Carrier session APIs
============================

Data types
----------

CarrierStreamType
#################

.. doxygenenum:: CarrierStreamType
   :project: CarrierAPI

CarrierStreamState
##################

.. doxygenenum:: CarrierStreamState
   :project: CarrierAPI

CandidateType
#############

.. doxygenenum:: CandidateType
   :project: CarrierAPI

NetworkTopology
###############

.. doxygenenum:: NetworkTopology
   :project: CarrierAPI

CarrierAddressInfo
##################

.. doxygenstruct:: CarrierAddressInfo
   :project: CarrierAPI
   :members:

CarrierTransportInfo
####################

.. doxygenstruct:: CarrierTransportInfo
   :project: CarrierAPI
   :members:

PortForwardingProtocol
######################

.. doxygenenum:: PortForwardingProtocol
   :project: CarrierAPI

CloseReason
###########

.. doxygenenum:: CloseReason
   :project: CarrierAPI

CarrierStreamCallbacks
######################

.. doxygenstruct:: CarrierStreamCallbacks
   :project: CarrierAPI
   :members:

CarrierSessionRequestCallback
#############################

.. doxygentypedef:: CarrierSessionRequestCallback
   :project: CarrierAPI

CarrierSessionRequestCompleteCallback
#####################################

.. doxygentypedef:: CarrierSessionRequestCompleteCallback
   :project: CarrierAPI

Functions
---------

Global session functions
########################

carrier_session_init
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_init
   :project: CarrierAPI

carrier_session_cleanup
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_cleanup
   :project: CarrierAPI

Session instance functions
##########################

carrier_session_new
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_new
   :project: CarrierAPI

carrier_session_close
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_close
   :project: CarrierAPI


carrier_session_get_peer
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_get_peer
   :project: CarrierAPI

carrier_session_set_userdata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_set_userdata
   :project: CarrierAPI

carrier_session_get_userdata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction::carrier_session_get_userdata
   :project: CarrierAPI

carrier_session_request
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_request
   :project: CarrierAPI


carrier_session_reply_request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_reply_request
   :project: CarrierAPI

carrier_session_start
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_start
   :project: CarrierAPI

Stream functions
################

Carrier_session_add_stream
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_add_stream
   :project: CarrierAPI

carrier_session_remove_stream
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_remove_stream
   :project: CarrierAPI

carrier_stream_get_type
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_get_type
   :project: CarrierAPI

carrier_stream_get_state
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_get_state
   :project: CarrierAPI

carrier_stream_get_transport_info
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_get_transport_info
   :project: CarrierAPI

carrier_stream_write
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_write
   :project: CarrierAPI

carrier_stream_open_channel
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_open_channel
   :project: CarrierAPI

carrier_stream_close_channel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_close_channel
   :project: CarrierAPI

carrier_stream_write_channel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_write_channel
   :project: CarrierAPI

carrier_stream_pend_channel
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_pend_channel
   :project: CarrierAPI

carrier_stream_resume_channel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_resume_channel
   :project: CarrierAPI

PortForwarding functions
########################

carrier_session_add_service
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_add_service
   :project: CarrierAPI

carrier_session_remove_service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_session_remove_service
   :project: CarrierAPI

carrier_stream_open_port_forwarding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_open_port_forwarding
   :project: CarrierAPI

carrier_stream_close_port_forwarding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: carrier_stream_close_port_forwarding
   :project: CarrierAPI

