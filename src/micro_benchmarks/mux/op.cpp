#include "../common/common.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"

encrypto::motion::ShareWrapper DummyBmrShare(encrypto::motion::PartyPointer& party,
                                             std::size_t number_of_wires,
                                             std::size_t number_of_simd) {
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto& w : wires) {
    auto bmr_wire{std::make_shared<encrypto::motion::proto::bmr::Wire>(dummy_input, *backend)};
    w = bmr_wire;
    register_pointer->RegisterWire(bmr_wire);
    bmr_wire->GetMutablePublicKeys() = encrypto::motion::Block128Vector::MakeZero(
        backend->GetConfiguration()->GetNumOfParties() * number_of_simd);
    bmr_wire->GetMutableSecretKeys() = encrypto::motion::Block128Vector::MakeZero(number_of_simd);
    bmr_wire->GetMutablePermutationBits() = encrypto::motion::BitVector<>(number_of_simd);
    bmr_wire->SetSetupIsReady();
    bmr_wire->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::bmr::Share>(wires));
}

encrypto::motion::ShareWrapper DummyBooleanGmwShare(encrypto::motion::PartyPointer& party,
                                                    std::size_t number_of_wires,
                                                    std::size_t number_of_simd) {
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto& w : wires) {
    w = std::make_shared<encrypto::motion::proto::boolean_gmw::Wire>(dummy_input, *backend);
    register_pointer->RegisterWire(w);
    w->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::boolean_gmw::Share>(wires));
}

encrypto::motion::ShareWrapper CreateOPCircuit(
    encrypto::motion::ShareWrapper a, encrypto::motion::ShareWrapper b, 
    encrypto::motion::PartyPointer& party, encrypto::motion::MpcProtocol protocol) {
  encrypto::motion::ShareWrapper selection{protocol ==
                                                       encrypto::motion::MpcProtocol::kBooleanGmw
                                                   ? DummyBooleanGmwShare(party, 1, 1)
                                                   : DummyBmrShare(party, 1, 1)};
  return selection.Mux(a, b);
}