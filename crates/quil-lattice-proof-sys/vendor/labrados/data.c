#include "data.h"

#if LOGQ == 32
#include "data32.c"
#elif LOGQ == 36
#include "data36.c"
#elif LOGQ == 38
#include "data38.c"
#endif
