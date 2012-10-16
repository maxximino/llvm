#ifndef LLVM_NCFAALL_H
#define LLVM_NCFAALL_H

#include <cstdlib>

#include "TaggedData.h"
#include "PropagaMetadati.h"
#include "DFGPrinter.h"
#include "MaxTestPass.h"

namespace {
  struct NCFAForcePassLinking {
    NCFAForcePassLinking() {
      // We must reference the passes in such a way that compilers will not
      // delete it all as dead code, even with whole program optimization,
      // yet is effectively a NO-OP. As the compiler isn't smart enough
      // to know that getenv() never returns -1, this will do the job.
      if (std::getenv("bar") != (char*) -1)
        return;

      (void) llvm::createPropagaMetadatiPass();
      (void) llvm::createTaggedDataPass();
      (void) llvm::createDFGPrinterPass();
      (void) llvm::createMaxTestPass();
    }
  } NCFAForcePassLinking; // Force link by creating a global definition.
}

#endif


