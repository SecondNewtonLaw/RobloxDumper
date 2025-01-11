cmake_minimum_required(VERSION 3.8)
project(RobloxDumper CXX)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

option(CAPSTONE_X86_SUPPORT "Enable x86 capstone" ON)

set(BUILD_SHARED_LIBS OFF)
set(CMAKE_CXX_STANDARD 23)

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)

if (build_type STREQUAL release)
    message("Build is in Release Mode; Adding custom Compiler options and Linker options.")
    add_compile_options(
            /GA
            /bigobj
            /O2
            /Gr
            /GS
            /cgthreads8
            /arch:AVX2
    )

    add_link_options(
            /LTCG
            /INCREMENTAL
            /DEBUG
            /DYNAMICBASE
            /HIGHENTROPYVA
            /GUARD:CF
            /PDB:RobloxDumper.pdb
            /VERBOSE
    )
endif ()

add_executable(${PROJECT_NAME}
        Entry.cpp
        Logger.cpp
        Logger.hpp
        Utilities.cpp
        Utilities.hpp

        # RobloxDumper Settings for EXE building.
        Settings.hpp

        # RobloxDumper/Analysis
        Analysis/Disassembler.cpp
        Analysis/Disassembler.hpp
        Analysis/StringSearcher.cpp
        Analysis/StringSearcher.hpp
        Analysis/XrefSearcher.cpp
        Analysis/XrefSearcher.hpp

        SignatureMatcher.cpp
        SignatureMatcher.hpp

        DumperState.cpp
        DumperState.hpp

        AnalysisTasks/TaskBase.hpp

        AnalysisTasks/VMShuffles/VmShuffle3And5.cpp
        AnalysisTasks/VMShuffles/VmShuffle3And5.hpp

        AnalysisTasks/VMShuffles/VmShuffle7And8.cpp
        AnalysisTasks/VMShuffles/VmShuffle7And8.hpp
        StringMatcher.cpp
        StringMatcher.hpp
        AnalysisTasks/VMShuffles/VmShuffle6.cpp
        AnalysisTasks/VMShuffles/VmShuffle6.hpp
        AnalysisTasks/VMValues/GlobalState.cpp
        AnalysisTasks/VMValues/GlobalState.hpp
        AnalysisTasks/VMShuffles/VmShuffle4.cpp
        AnalysisTasks/VMShuffles/VmShuffle4.hpp
)

target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/Dependencies")

# Dependencies

# libhat
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/libhat")

# capstone
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Capstone")

target_link_libraries(${PROJECT_NAME}
        PUBLIC
        # libhat -- https://github.com/BasedInc/libhat
        libhat

        capstone
)

