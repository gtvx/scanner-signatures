#ifndef TYPES_H
#define TYPES_H

typedef void *HANDLE;

typedef char int8;
typedef short int16;
typedef long int32;

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned long uint32;

#ifndef WIN64
typedef signed long SIGNED_ADDRESS;
typedef unsigned long ADDRESS;
typedef unsigned long _SIZE;
#else
typedef signed long long SIGNED_ADDRESS;
typedef unsigned long long ADDRESS;
typedef unsigned long long _SIZE;
#endif

enum BIT { _32bit, _64bit };

typedef unsigned char Bool;

#ifndef __cplusplus

#ifndef false
#define false 0
#endif

#ifndef true
#define true 1
#endif

#endif

#endif // TYPES_H
