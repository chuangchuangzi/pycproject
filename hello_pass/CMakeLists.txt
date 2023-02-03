include(AddLLVM)
add_llvm_library(ArgParse MODULE hello_pass.cpp PLUGIN_TOOL clang)
target_compile_features(ArgParse PRIVATE cxx_range_for cxx_auto_type)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)