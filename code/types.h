/*==================================================================================================
  File: types.h
  Creation Date: 2018-03-13
  Creator: Michael Campagnaro
  Notice: (C) Copyright 2018 by Jelly Pixel, Inc. All Rights Reserved.
  ================================================================================================*/

#include <stdint.h>

#ifndef __cplusplus
typedef enum { false, true } bool;
#endif

// @question Possibly switch to int_fast<num>_t types. What are the implications?
typedef int8_t  i8;
typedef int8_t  s8;
typedef int8_t  s08;
typedef int16_t i16;
typedef int16_t s16;
typedef int32_t i32;
typedef int32_t s32;
typedef int64_t i64;
typedef int64_t s64;
typedef int32_t b32;

typedef uint8_t  u8;
typedef uint8_t  u08;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef float  real32;
typedef double real64;
typedef real32 f32;
typedef real64 f64;
