#ifndef ML_KEM_H
#define ML_KEM_H

#include "../pqc_common.h"

#define ML_KEM_LABEL "ml-kem-768"

int ml_kem_run(PQCKEMResult *result);
void ml_kem_result_free(PQCKEMResult *result);

#endif
