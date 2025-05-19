#!/bin/bash

fileName="${1%%.*}" # to remove .s extension

nasm -f elf64 ${fileName}".s"
ld ${fileName}".o" -o ${fileName}
[ "$2" == "-g" ] && gdb -q ./${fileName} || ./${fileName}
