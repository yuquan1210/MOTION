add_executable(inv op.cpp ../common/common_main.cpp ../common/common.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(inv
        MOTION::motion
        Boost::program_options
        )
