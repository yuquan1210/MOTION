#include "../common/common.h"

encrypto::motion::ShareWrapper CreateOPCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b, 
    encrypto::motion::PartyPointer& party, encrypto::motion::MpcProtocol protocol) {
  return ~(a == b);
}