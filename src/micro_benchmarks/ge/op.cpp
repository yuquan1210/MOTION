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

encrypto::motion::ShareWrapper CreateGTCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b) {
  encrypto::motion::ShareWrapper result;
  encrypto::motion::SecureUnsignedInteger secure_uint_a = encrypto::motion::SecureUnsignedInteger(a);
  encrypto::motion::SecureUnsignedInteger secure_uint_b = encrypto::motion::SecureUnsignedInteger(b);
  encrypto::motion::SecureUnsignedInteger secure_uint_result = secure_uint_a > secure_uint_b;
  encrypto::motion::ShareWrapper sharewrapper_result = secure_uint_result.Get();
  return sharewrapper_result;
}

encrypto::motion::ShareWrapper CreateOPCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b, 
    encrypto::motion::PartyPointer& party, encrypto::motion::MpcProtocol protocol) {
  encrypto::motion::ShareWrapper result;
  encrypto::motion::ShareWrapper eq_result, gt_result, eq_out, gt_out;
  gt_result = CreateGTCircuit(a, b);
  //gt_out = gt_result.Out();
  eq_result = CreateEQCircuit(a, b);
  //eq_out = eq_result.Out();
  //std::cout << "EQResult = " << ((eq_result.Out()).As<bool>()) << std::endl;
  //std::cout << "GTResult = " << ((gt_result.Out()).As<bool>()) << std::endl;
  result = CreateORCircuit(eq_result, gt_result);
  return result;
}