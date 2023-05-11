add_executable(gt op.cpp ../common/common_main.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(gt
        MOTION::motion
        Boost::program_options
        )
