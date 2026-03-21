# Фильтровать повторное подключение таргета
include_guard(GLOBAL)

# Определить имя таргета проекта
set(TARGET_NAME ArNet)

# Подключить модуль работы с исходниками
include(GeneralSettings)

#=========================== Настройки таргетов =================================

# Подключить модуль работы с исходниками
include(SourceSettings)

# Определить таргет проекта
add_kivk_library(TARGET_NAME ${TARGET_NAME})

# Задать исходники таргету
set_sources_to_target(PRIVATE TARGET_NAME ${TARGET_NAME})

#============================= Библиотеки =======================================

set_interface_to_target(PUBLIC TARGET_NAME ${TARGET_NAME} INTERFACE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/interface)

# Подключить модуль библиотек
include(LibsSettings)

## Подключить сторонние библиотеки
link_subdir_libraries(
    PUBLIC
    TARGET_NAME ${TARGET_NAME}
    MODULE_PATH ${_PATH_TO_MODULES}/origin_lib_prot_msg
    MODULE_TARGETS "Protocol"
)
