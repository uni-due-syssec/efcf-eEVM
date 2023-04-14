cmake_minimum_required(VERSION 3.10)

set(CMAKE_AR llvm-ar )
set(CMAKE_RANLIB llvm-ranlib )
set(CMAKE_C_COMPILER_AR "${CMAKE_AR}" )
set(CMAKE_CXX_COMPILER_AR "${CMAKE_AR}" )
set(CMAKE_C_COMPILER_RANLIB "${CMAKE_RANLIB}" )
set(CMAKE_CXX_COMPILER_RANLIB "${CMAKE_RANLIB}" )

project(eevm)

option(LIBFUZZER "enable libfuzzer" OFF)
option(ENABLE_FUZZING "Enable Fuzzing Targets" OFF)
option(DUMP_LTO_BITCODE "Dump llvm LTO bitcode" OFF)
option(ENABLE_DETECTOR "Enable Detectors (i.e. Custom Bug Oracles)" OFF)
option(ENABLE_ASAN "Enable Address Sanitizer for testing bugs in the EVM implementation" OFF)
option(FUZZ_INTERP "Run fuzzing with interpreter instead of the specialized executor" OFF)

set(LTO_LINKER_NAME "lld" CACHE STRING "which linker to use for LTO (lld|gold)")
set(FUZZ_DRIVER_LIB "" CACHE FILEPATH "Path to Driver library of fuzzer")
set(FUZZ_TARGET "nop" CACHE STRING "Target smart contract for fuzzing")

set(CMAKE_CXX_STANDARD 17)

function(append value)
    foreach(variable ${ARGN})
        set(${variable} "${${variable}} ${value}" PARENT_SCOPE)
    endforeach(variable)
endfunction()



if(MSVC)
  # Set Windows compiler options.
  add_compile_options(/W3 /std:c++latest)
else()
  # Set Linux compiler options
  add_compile_options(-Wall)

  if (ENABLE_ASAN)
      add_compile_options(-fsanitize=address)
      append("-fsanitize=address" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
  endif()

  # enable -Werror only on non-release builds, otherwise
  # we get problems with variables that are used in assert()
  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
      add_compile_options(-Wno-bitwise-instead-of-logical -Werror)
  endif()
  
  message("[INFO] Using COMPILER_ID ${CMAKE_CXX_COMPILER_ID}")

  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    separate_arguments(COVERAGE_FLAGS UNIX_COMMAND "--coverage -fprofile-arcs -ftest-coverage")
    set(PLATFORM_SPECIFIC_TEST_LIBS "gcov")
  else()
    separate_arguments(COVERAGE_FLAGS UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping")
    set(PLATFORM_SPECIFIC_TEST_LIBS "-fprofile-instr-generate")
  endif()

  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")

    #add_compile_options(-time -save-stats -mllvm --time-passes -Wl,-mllvm=--time-passes)

    # Enable Link-Time Optimization, AKA Inter-Procedure Optimization
    if(NOT ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug"))
        include(CheckIPOSupported)
        check_ipo_supported(RESULT LTOAvailable)
        message("[INFO] LTO is available: ${LTOAvailable}")
    #endif()
    #if(LTOAvailable)
        message("[INFO] Link-time optimization enabled with linker -fuse-ld=${LTO_LINKER_NAME}")

        #set_property(TARGET eevm PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
        append("-fuse-ld=${LTO_LINKER_NAME} -flto=full" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
        add_compile_options(-flto=full)
        if(DUMP_LTO_BITCODE)
            append("-Wl,--plugin-opt=-lto-embed-bitcode=optimized" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
            add_compile_options(-Wl,--plugin-opt=-lto-embed-bitcode=optimized)
        endif()

        append("-O3 -march=native -mtune=native -fvisibility-inlines-hidden" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
        add_compile_options(-O3 -march=native -mtune=native -fvisibility-inlines-hidden)
        
        if(ENABLE_FUZZING)
        
            append("-g" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
            add_compile_options(-g)
      
            # Some currently unused de-optimization flags for the compiler...
            #
            #message("[WARN] disable some compiler optimizations that are detrimental to fuzzing")
            #append("-fno-slp-vectorize" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
            #add_compile_options(-fno-slp-vectorize)
            #append("-fno-vectorize" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
            #add_compile_options(-fno-vectorize)
            #append("-mllvm --disable-mergeicmps" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
            #add_compile_options("SHELL:-mllvm --disable-mergeicmps")
            
            message("[WARN] setting CMAKE_*_{AR,RANLIB}")
            # weirdly, if we use hfuzz-clang and -flto then cmake cannot find the right
            # ar or something. So we explicitely set the llvm variants of this
            set(CMAKE_AR llvm-ar )
            set(CMAKE_RANLIB llvm-ranlib )
            set(CMAKE_C_COMPILER_AR "${CMAKE_AR}" )
            set(CMAKE_CXX_COMPILER_AR "${CMAKE_AR}" )
            set(CMAKE_C_COMPILER_RANLIB "${CMAKE_RANLIB}" )
            set(CMAKE_CXX_COMPILER_RANLIB "${CMAKE_RANLIB}" )
       
            # if we are fuzzing, we use a custom allowlist to avoid
            # instrumenting unuseful things.
            #append("-fsanitize-coverage-allowlist=fuzz-cov-allowlist.txt" CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
            #add_compile_options(-fsanitize-coverage-allowlist=fuzz-cov-allowlist.txt)
        endif()
    endif()
  endif()
endif()


if(ENABLE_FUZZING)
    # We have implemented several basic bug detection oracles; if we are
    # fuzzing we use the option to enable the detector code - note that this
    # will break normal EVM executions as it assumes that certain actions are
    # illegal while they are actually fine within the EVM spec
    if(ENABLE_DETECTOR)
        add_compile_definitions(ENABLE_DETECTOR)
    endif()
        
    add_compile_definitions(ENABLE_FUZZING)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB KECCAK_SOURCES
  3rdparty/keccak/*.c
)

set(MPACK_SOURCES 3rdparty/mpack/src/mpack/mpack.c)

file(GLOB EVM2CPP_SOURCES
  contracts/*.cpp
)

add_subdirectory(3rdparty)

# find the system package for mimalloc
find_package(mimalloc REQUIRED)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Options 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
option(RECORD_TRACE "Record a detailed trace of EVM execution during test runs" OFF)
if(RECORD_TRACE)
  add_definitions(-DRECORD_TRACE)
endif(RECORD_TRACE)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Common variables 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
set(EEVM_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty
  ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/parallel-hashmap/
  ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/mpack/src/mpack/
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(EEVM_CORE_SRCS
  src/disassembler.cpp
  src/processor.cpp
  src/stack.cpp
  src/transaction.cpp
  src/util.cpp
  src/detector.cpp
)

set(EEVM_SIMPLE_SRCS
  src/simple/simpleaccount.cpp
  src/simple/simpleglobalstate.cpp
  src/simple/simplestorage.cpp
  src/simple/msgpacker.cpp
  ${MPACK_SOURCES}
)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Libraries
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
add_library(eevm STATIC
  ${EEVM_CORE_SRCS}
  ${KECCAK_SOURCES}
  ${EVM2CPP_SOURCES}
)
target_include_directories(eevm PRIVATE
  ${EEVM_INCLUDE_DIRS}
)
target_link_libraries(eevm
  intx::intx
)

if (ENABLE_FUZZING)
    target_include_directories(eevm PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/common/
    )
endif()


if(NOT ENABLE_FUZZING)
    # unfortunately hfuzz-clang and testing is somehow broken, idk?

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Executables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    add_executable(eevm_tests
      tests/main.cpp
      tests/harness.cpp
      tests/rlp.cpp
      ${EEVM_SIMPLE_SRCS}
    )
    target_include_directories(eevm_tests PRIVATE
      ${EEVM_INCLUDE_DIRS}
    )
    target_compile_options(eevm_tests PRIVATE ${COVERAGE_FLAGS})
    target_link_libraries(eevm_tests eevm ${PLATFORM_SPECIFIC_TEST_LIBS})


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Tests
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    
    enable_testing()

    add_test(
      NAME eevm_tests
      COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit_test_wrapper.sh eevm_tests
    )

    if(NOT ENV{TEST_DIR}) 
      set_tests_properties(eevm_tests
        PROPERTIES
          ENVIRONMENT TEST_DIR=${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/test_cases
      )
    endif()
else()
    message("[WARNING] Disabling regular tests for fuzzing builds!")
endif()

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Samples
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function(add_sample name)
  add_executable(${name}
    samples/${name}/main.cpp
    ${EEVM_SIMPLE_SRCS}
  )
  target_include_directories(${name} PRIVATE
    ${EEVM_INCLUDE_DIRS}
  )
  target_link_libraries(${name} eevm)
endfunction()

#add_sample(hello_world)
#add_sample(sum)
#add_sample(erc20)
add_sample(disassembler)
# new and with specialized evm2cpp executor!
#add_sample(crowdsale)


function(add_fuzz_target name)
  set(exec_name "fuzz_${name}")
  add_executable(${exec_name}
    fuzz/${name}/main.cpp
    fuzz/common/fuzz_init.cpp
    ${EEVM_SIMPLE_SRCS}
    ${EEVM_CORE_SRCS}
    ${KECCAK_SOURCES}
    ${EVM2CPP_SOURCES}
  )
  
  target_link_libraries(${exec_name} intx::intx)
  target_include_directories(${exec_name} PUBLIC
    ${EEVM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/common/
    ${MIMALLOC_INCLUDE_DIR}
  )

  if(FUZZ_INTERP)
    message("fuzzing with interpreter enabled for ${exec_name}")
    target_compile_definitions(${exec_name} PRIVATE FUZZ_WITH_INTERPRETER=1)
  endif()

  target_compile_definitions(${exec_name} PRIVATE DEOPTIMIZE_INTX=1 ENABLE_FUZZING=1)
  #target_compile_definitions(${exec_name} PRIVATE TARGET_CONTRACT=${FUZZ_TARGET})
  set_source_files_properties(fuzz/${name}/main.cpp PROPERTIES COMPILE_DEFINITIONS TARGET_CONTRACT=${FUZZ_TARGET})
  set_source_files_properties(fuzz/common/fuzz_init.cpp PROPERTIES COMPILE_DEFINITIONS TARGET_CONTRACT=${FUZZ_TARGET})

  if("${FUZZ_DRIVER_LIB}" STREQUAL "" OR "${FUZZ_DRIVER_LIB}" STREQUAL "OFF")
    #target_link_libraries(${exec_name} eevm)
  else()
    target_link_libraries(${exec_name} ${FUZZ_DRIVER_LIB})
  endif()
    
  target_link_libraries(${exec_name} 
    intx::intx
    mimalloc
  )

  # run libfuzzer
  if(LIBFUZZER)
    message("libfuzzer enabled for ${exec_name}")
    target_compile_options(${exec_name} PRIVATE -fsanitize=fuzzer-no-link -fsanitize-coverage-blacklist=fuzz-cov-blocklist.txt)
    target_link_options(${exec_name} PRIVATE -fsanitize=fuzzer -fsanitize-coverage-blacklist=fuzz-cov-blocklist.txt)
  endif()

endfunction()

if(ENABLE_FUZZING)

  configure_file(fuzz/cov-allowlist.txt fuzz-cov-allowlist.txt COPYONLY)
  configure_file(fuzz/cov-blocklist.txt fuzz-cov-blocklist.txt COPYONLY)

  message("[INFO] Enabling Fuzzing for contract '${FUZZ_TARGET}'!")
  #add_fuzz_target(simpledao)
  #add_fuzz_target(differential)
  
  add_fuzz_target(multitx)

endif()
