#!/usr/bin/bash
gcc main.c -o tinypage -Wall -Werror -Wfatal-errors -O3 -flto -fomit-frame-pointer -march=native -mtune=native