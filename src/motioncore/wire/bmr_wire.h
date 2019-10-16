// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include "wire.h"

#include "utility/bit_vector.h"

namespace ENCRYPTO {
class Condition;
}

namespace MOTION::Wires {

class BMRWire : public BooleanWire {
 public:
  BMRWire(const std::size_t n_simd, std::weak_ptr<Backend> backend, bool is_constant = false);

  BMRWire(ENCRYPTO::BitVector<> &&values, std::weak_ptr<Backend> backend, bool is_constant = false);

  BMRWire(const ENCRYPTO::BitVector<> &values, std::weak_ptr<Backend> backend,
          bool is_constant = false);

  BMRWire(bool value, std::weak_ptr<Backend> backend, bool is_constant = false);

  ~BMRWire() final = default;

  MPCProtocol GetProtocol() const final { return MPCProtocol::BMR; }

  BMRWire() = delete;

  BMRWire(BMRWire &) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const ENCRYPTO::BitVector<> &GetPublicValues() const { return public_values_; }

  ENCRYPTO::BitVector<> &GetMutablePublicValues() { return public_values_; }

  const ENCRYPTO::BitVector<> &GetPermutationBits() const { return shared_permutation_bits_; }

  ENCRYPTO::BitVector<> &GetMutablePermutationBits() { return shared_permutation_bits_; }

  const auto &GetSecretKeys() const { return secret_keys_; }

  auto &GetMutableSecretKeys() { return secret_keys_; }

  const auto &GetPublicKeys() const { return public_keys_; }

  auto &GetMutablePublicKeys() { return public_keys_; }

  void GenerateRandomPrivateKeys();

  void GenerateRandomPermutationBits();

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_cond_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_cond_->NotifyAll();
  }

  auto &GetSetupReadyCondition() { return setup_ready_cond_; }

 protected:
  void DynamicClear() final { setup_ready_ = false; }

 private:
  void InitializationHelperBMR();

  // also store the cleartext values in public_values_ if the wire is the outp
  ENCRYPTO::BitVector<> public_values_, shared_permutation_bits_;
  std::pair<std::vector<ENCRYPTO::BitVector<>>, std::vector<ENCRYPTO::BitVector<>>> secret_keys_;
  // for each party for each bit
  std::vector<std::vector<ENCRYPTO::BitVector<>>> public_keys_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<ENCRYPTO::Condition> setup_ready_cond_;
};

using BMRWirePtr = std::shared_ptr<BMRWire>;
}  // namespace MOTION::Wires