add_executable(costco costco.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
	find_package(Boost
			COMPONENTS
			program_options
			REQUIRED)
endif ()

target_link_libraries(costco
		MOTION::motion
		Boost::program_options
		)

