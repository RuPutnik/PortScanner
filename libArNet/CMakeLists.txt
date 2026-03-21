# Определить минимально допустимую версию CMake для данного проекта
cmake_minimum_required(VERSION 3.16)

# Определить текущий проект
project(libArNet
        VERSION 1.0
        DESCRIPTION "Библиотека работы с сетью"
        LANGUAGES CXX
)

# Определить путь к модулям и библиотекам
set(_PATH_TO_MODULES "${PROJECT_SOURCE_DIR}/modules" CACHE STRING "Путь к используемым внешним модулям")

# Настроить возможность подключения модулей cmake
include(${_PATH_TO_MODULES}/origin_tlk_build/cmake/Init.cmake)

# Подключить исходники
add_subdirectory(src)

# Подключить тесты
if(NOT CMAKE_BUILD_TYPE MATCHES "ReleaseInstall")
    add_subdirectory(tests)
endif()
