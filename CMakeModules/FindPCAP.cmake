IF (WIN32)
	FIND_PATH(PCAP_INC_DIR
		NAMES "pcap.h"
		PATHS "${CMAKE_SOURCE_DIR}/WinPcap/include")
	
	FIND_LIBRARY(PCAP_LIB1
		NAMES "Packet"
		PATHS "${CMAKE_SOURCE_DIR}/WinPcap/lib")
	
	FIND_LIBRARY(PCAP_LIB2
		NAMES "wpcap"
		PATHS "${CMAKE_SOURCE_DIR}/WinPcap/lib")
		
	SET(PCAP_LIB "${PCAP_LIB1}" "${PCAP_LIB2}")
ELSE()
	FIND_PATH(PCAP_INC_DIR
		NAMES "pcap.h"
		PATHS "/usr/include/pcap" "/usr/local/include/pcap")
		
	FIND_LIBRARY(PCAP_LIB
		NAMES "pcap"
		PATHS "/usr/lib" "/lib" "/usr/local/lib")
ENDIF()


IF ("${PCAP_INC_DIR}" STREQUAL "")
	MESSAGE(FATAL "Pcap include not found")
ENDIF()

IF ("${PCAP_LIB}" STREQUAL "")
	MESSAGE(FATAL "Pcap lib not found")
ENDIF()
