add_executable(1clik_bio 1clik_bio.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
	find_package(Boost
			COMPONENTS
			program_options
			REQUIRED)
endif ()

target_link_libraries(1clik_bio
		MOTION::motion
		Boost::program_options
		)

