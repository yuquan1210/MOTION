#include "../common/common.h"

encrypto::motion::ShareWrapper CreateOPCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b, 
    encrypto::motion::PartyPointer& party, encrypto::motion::MpcProtocol protocol) {
  encrypto::motion::SecureUnsignedInteger secure_uint_a = encrypto::motion::SecureUnsignedInteger(a);
  encrypto::motion::SecureUnsignedInteger secure_uint_b = encrypto::motion::SecureUnsignedInteger(b);
  encrypto::motion::SecureUnsignedInteger secure_uint_result = secure_uint_a + secure_uint_b;
  encrypto::motion::ShareWrapper sharewrapper_result = secure_uint_result.Get();
  return sharewrapper_result;
}