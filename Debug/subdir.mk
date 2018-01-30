################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../RIPEMD160.c \
../common.c \
../sha224-test.c \
../sha256-all.c \
../sha256-test.c \
../sha256.c \
../sha256_func_bounce.c \
../sha256_func_expansion.c \
../sha256_func_round.c \
../sha256_generate_train_files.c \
../sha256_inverse.c \
../sha256_lisible.c \
../sha256_test.c \
../sha384-test.c \
../sha512-test.c \
../sha512.c \
../timer.c \
../tree.c 

OBJS += \
./RIPEMD160.o \
./common.o \
./sha224-test.o \
./sha256-all.o \
./sha256-test.o \
./sha256.o \
./sha256_func_bounce.o \
./sha256_func_expansion.o \
./sha256_func_round.o \
./sha256_generate_train_files.o \
./sha256_inverse.o \
./sha256_lisible.o \
./sha256_test.o \
./sha384-test.o \
./sha512-test.o \
./sha512.o \
./timer.o \
./tree.o 

C_DEPS += \
./RIPEMD160.d \
./common.d \
./sha224-test.d \
./sha256-all.d \
./sha256-test.d \
./sha256.d \
./sha256_func_bounce.d \
./sha256_func_expansion.d \
./sha256_func_round.d \
./sha256_generate_train_files.d \
./sha256_inverse.d \
./sha256_lisible.d \
./sha256_test.d \
./sha384-test.d \
./sha512-test.d \
./sha512.d \
./timer.d \
./tree.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I"/home/malego/Projects/workspace/mylibc/Include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


