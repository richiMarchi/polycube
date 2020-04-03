include(${PROJECT_SOURCE_DIR}/cmake/LoadFileAsVariable.cmake)

aux_source_directory(serializer SERIALIZER_SOURCES)
aux_source_directory(api API_SOURCES)
aux_source_directory(base BASE_SOURCES)

include_directories(serializer)

if (NOT DEFINED POLYCUBE_STANDALONE_SERVICE OR POLYCUBE_STANDALONE_SERVICE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(POLYCUBE libpolycube)
  include_directories(${POLYCUBE_INCLUDE_DIRS})
endif(NOT DEFINED POLYCUBE_STANDALONE_SERVICE OR POLYCUBE_STANDALONE_SERVICE)

# Needed to load files as variables
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(pcn-p4firewall SHARED
  ${SERIALIZER_SOURCES}
  ${API_SOURCES}
  ${BASE_SOURCES}
  FlowDirection.cpp
  P4firewall.cpp
  Ports.cpp
  Route.cpp
  P4firewall-lib.cpp)

# load ebpf datapath code a variable
load_file_as_variable(pcn-p4firewall
  P4firewall_dp.c
  p4firewall_code)

# load datamodel in a variable
load_file_as_variable(pcn-p4firewall
  ../datamodel/p4firewall.yang
  p4firewall_datamodel)

target_link_libraries(pcn-p4firewall ${POLYCUBE_LIBRARIES})

# Specify shared library install directory

set(CMAKE_INSTALL_LIBDIR /usr/lib)

install(
    TARGETS
    pcn-p4firewall
    DESTINATION
    "${CMAKE_INSTALL_LIBDIR}"
)
