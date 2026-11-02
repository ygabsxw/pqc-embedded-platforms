#ifndef CLASSIC_MCELIECE_H
#define CLASSIC_MCELIECE_H

#include "../pqc_common.h"

#define CLASSIC_MCELIECE_LABEL "classic-mceliece-348864"

int classic_mceliece_run(PQCKEMResult *result);
void classic_mceliece_result_free(PQCKEMResult *result);

#endif
