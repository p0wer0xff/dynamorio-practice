set(sample_compile_options -O0 -no-pie)
set(DynamoRIO_DIR build_dr/cmake)
find_package(DynamoRIO)

add_executable(sample_branches sample_programs/branches.c)
target_compile_options(sample_branches PRIVATE ${sample_compile_options})

add_executable(sample_calls sample_programs/calls.c)
target_compile_options(sample_calls PRIVATE ${sample_compile_options})

add_executable(sample_hello_world sample_programs/hello_world.c)
target_compile_options(sample_hello_world PRIVATE ${sample_compile_options})

add_executable(sample_loop sample_programs/loop.c)
target_compile_options(sample_loop PRIVATE ${sample_compile_options})

add_executable(sample_detect sample_programs/detect.c)
target_compile_options(sample_detect PRIVATE ${sample_compile_options})

add_library(count_bb_unique SHARED count_bb_unique.c)
configure_DynamoRIO_client(count_bb_unique)
use_DynamoRIO_extension(count_bb_unique drmgr)

add_library(count_bb_total SHARED count_bb_total.c)
configure_DynamoRIO_client(count_bb_total)
use_DynamoRIO_extension(count_bb_total drmgr)
use_DynamoRIO_extension(count_bb_total drreg)

add_library(count_bb_total_module SHARED count_bb_total_module.c modules.c)
configure_DynamoRIO_client(count_bb_total_module)
use_DynamoRIO_extension(count_bb_total_module drmgr)
use_DynamoRIO_extension(count_bb_total_module drreg)

add_library(edge_coverage SHARED edge_coverage.c modules.c)
configure_DynamoRIO_client(edge_coverage)
use_DynamoRIO_extension(edge_coverage drmgr)
use_DynamoRIO_extension(edge_coverage drreg)