#pragma once
#include <stdio.h>
#include <string>
#include <cstdint>
#include <stdarg.h>

#define println(x, ...)  \
    printf(x, ##__VA_ARGS__);   \
    printf("\n");
