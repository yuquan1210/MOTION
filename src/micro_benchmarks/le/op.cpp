#include "../common/common.h"

encrypto::motion::ShareWrapper CreateORCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b) {
  encrypto::motion::ShareWrapper result;
  return a | b;
}

encrypto::motion::ShareWrapper CreateEQCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b) {
  encrypto::motion::ShareWrapper result;
  return a == b;
}

encrypto::motion::ShareWrapper CreateLTCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b) {
  encrypto::motion::ShareWrapper result;
  encrypto::motion::SecureUnsignedInteger secure_uint_a = encrypto::motion::SecureUnsignedInteger(a);
  encrypto::motion::SecureUnsignedInteger secure_uint_b = encrypto::motion::SecureUnsignedInteger(b);
  encrypto::motion::SecureUnsignedInteger secure_uint_result = secure_uint_b > secure_uint_a;
  encrypto::motion::ShareWrapper sharewrapper_result = secure_uint_result.Get();
  return sharewrapper_result;
}

encrypto::motion::ShareWrapper CreateOPCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b, 
    encrypto::motion::PartyPointer& party, encrypto::motion::MpcProtocol protocol) {
  encrypto::motion::ShareWrapper result;
  encrypto::motion::ShareWrapper eq_result, lt_result, eq_out, gt_out;
  lt_result = CreateLTCircuit(a, b);
  eq_result = CreateEQCircuit(a, b);
  result = CreateORCircuit(eq_result, lt_result);
  return result;
}