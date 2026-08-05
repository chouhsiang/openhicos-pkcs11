cmake_minimum_required(VERSION 3.16)
project(openhicos-pkcs11 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(openhicos-pkcs11 SHARED
	pkcs11/module.c
	pkcs11/oh_pcsc.c
	pkcs11/oh_apdu.c
	pkcs11/oh_der.c
	pkcs11/oh_sha.c
	pkcs11/oh_p15.c
	$<$<BOOL:${WIN32}>:pkcs11/openhicos.def>
)

target_include_directories(openhicos-pkcs11 PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${CMAKE_CURRENT_SOURCE_DIR}/pkcs11
)

if(MSVC)
	target_compile_definitions(openhicos-pkcs11 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Derive openhicos-pkcs11-<os>-<arch> output name
if(APPLE)
	set(_OH_OS "macos")
elseif(WIN32)
	set(_OH_OS "windows")
else()
	set(_OH_OS "linux")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
	set(_OH_ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
	set(_OH_ARCH "x86_64")
else()
	set(_OH_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(_OH_OUT "openhicos-pkcs11-${_OH_OS}-${_OH_ARCH}")

if(APPLE)
	find_library(PCSC_LIBRARY PCSC REQUIRED)
	target_link_libraries(openhicos-pkcs11 PRIVATE ${PCSC_LIBRARY})
	set_target_properties(openhicos-pkcs11 PROPERTIES
		OUTPUT_NAME "${_OH_OUT}"
		PREFIX ""
		SUFFIX ".so"
		MACOSX_RPATH ON
	)
	target_link_options(openhicos-pkcs11 PRIVATE
		LINKER:-exported_symbol,_C_GetFunctionList
	)
elseif(WIN32)
	target_link_libraries(openhicos-pkcs11 PRIVATE Winscard)
	set_target_properties(openhicos-pkcs11 PROPERTIES
		OUTPUT_NAME "${_OH_OUT}"
		PREFIX ""
		SUFFIX ".so"
	)
else()
	find_library(PCSCLITE_LIBRARY pcsclite REQUIRED)
	target_link_libraries(openhicos-pkcs11 PRIVATE ${PCSCLITE_LIBRARY})
	set_target_properties(openhicos-pkcs11 PROPERTIES
		OUTPUT_NAME "${_OH_OUT}"
		PREFIX ""
		SUFFIX ".so"
	)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

install(TARGETS openhicos-pkcs11
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION lib
	ARCHIVE DESTINATION lib
)
