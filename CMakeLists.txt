add_executable(asv_test asv_test.cpp common/biometric.cpp common/biometric_distances.cpp common/biometric_file.cpp common/CircuitWrapper.cpp)
target_link_libraries(asv_test ABY::aby ENCRYPTO_utils::encrypto_utils)
