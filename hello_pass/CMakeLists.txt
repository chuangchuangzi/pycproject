add_library(HelloPass MODULE hello_pass.cpp)
set_target_properties(HelloPass PROPERTIES
    COMPILE_FLAGS "-fno-rtti"
)