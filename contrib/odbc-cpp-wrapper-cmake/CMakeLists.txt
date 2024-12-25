SET(LIBRARY_DIR "${CMAKE_SOURCE_DIR}/contrib/odbc-cpp-wrapper")

add_library(_odbc-cpp-wrapper
        "${LIBRARY_DIR}/src/odbc/Connection.cpp"
)

file(GLOB APP_SOURCES
        "${LIBRARY_DIR}/src/odbc/*.cpp"
        "${LIBRARY_DIR}/src/odbc/internal/*.cpp"
)
message("testsourcefile: start")

foreach (testsourcefile ${APP_SOURCES})
    message("testsourcefile: ${testsourcefile}")
    target_sources(_odbc-cpp-wrapper PRIVATE ${testsourcefile})
endforeach (testsourcefile ${APP_SOURCES})

target_include_directories(_odbc-cpp-wrapper SYSTEM BEFORE PUBLIC "${LIBRARY_DIR}" "${LIBRARY_DIR}/src" "${LIBRARY_DIR}/src/odbc" "${LIBRARY_DIR}/src/odbc/internal")

add_library(ch_contrib::odbc_cpp_wrapper ALIAS _odbc-cpp-wrapper)
