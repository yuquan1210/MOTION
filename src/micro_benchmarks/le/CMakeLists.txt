add_executable(le op.cpp ../common/common_main.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(le
        MOTION::motion
        Boost::program_options
        )
