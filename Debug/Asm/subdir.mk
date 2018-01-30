################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
S_UPPER_SRCS += \
../Asm/sha256-x8664.S \
../Asm/sha512-x8664.S 

OBJS += \
./Asm/sha256-x8664.o \
./Asm/sha512-x8664.o 


# Each subdirectory must supply rules for building sources it contributes
Asm/sha256-x8664.o: ../Asm/sha256-x8664.S
	@echo 'Building file: $<'
	@echo 'Invoking: GCC Assembler'
	gcc -nostartfiles -I"/home/malego/Projects/workspace/mylibc/Include" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Asm/sha512-x8664.o: ../Asm/sha512-x8664.S
	@echo 'Building file: $<'
	@echo 'Invoking: GCC Assembler'
	gcc -nostartfiles -I"/home/malego/Projects/workspace/mylibc/Include" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


