project(monad_event)

add_library(monad_event STATIC
    "category/core/format_err.c"
    "category/core/format_err.h"
    "category/core/srcloc.h"
    "category/core/event/event_iterator.h"
    "category/core/event/event_metadata.h"
    "category/core/event/event_ring.c"
    "category/core/event/event_ring.h"
    "category/core/event/event_ring_util.c"
    "category/core/event/event_ring_util.h"
    "category/execution/ethereum/core/base_ctypes.h"
    "category/execution/ethereum/core/eth_ctypes.h"
    "category/execution/ethereum/event/exec_event_ctypes.h"
    "category/execution/ethereum/event/exec_event_ctypes_metadata.c"
    "category/execution/ethereum/event/exec_iter_help.h")

target_include_directories(monad_event PUBLIC ${PROJECT_SOURCE_DIR})
target_compile_definitions(monad_event PUBLIC _GNU_SOURCE)
target_compile_features(monad_event PUBLIC c_std_23)
target_compile_options(monad_event PRIVATE -Wall -Wextra -Wconversion -Werror)

option(MONAD_EVENT_BUILD_EXAMPLE
    "Build the example program that shows how to use the API" ON)

if (MONAD_EVENT_BUILD_EXAMPLE)
    add_executable(eventwatch "example/eventwatch.c")
    target_link_libraries(eventwatch PRIVATE monad_event)
endif()
