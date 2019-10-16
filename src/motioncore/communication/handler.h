// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include <queue>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "flatbuffers/flatbuffers.h"

namespace ENCRYPTO {
class Condition;
template <typename T>
class LockedQueue;
}  // namespace ENCRYPTO

namespace MOTION {
class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

using IoServicePtr = std::shared_ptr<boost::asio::io_service>;
using BoostSocketPtr = std::shared_ptr<boost::asio::ip::tcp::socket>;

namespace Communication {
class Context;
using ContextPtr = std::shared_ptr<Context>;

class Handler {
 public:
  Handler() = delete;

  Handler(ContextPtr &context, const LoggerPtr &logger);

  virtual ~Handler();

  void SendMessage(flatbuffers::FlatBufferBuilder &&message);

  const BoostSocketPtr GetSocket();

  bool ContinueCommunication() { return continue_communication_; }

  void TerminateCommunication();

  void WaitForConnectionEnd();

  LoggerPtr &GetLogger() { return logger_; }

  const std::string &GetInfo() { return handler_info_; }

  bool VerifyHelloMessage();

  void Reset();

  void Clear();

  /// \brief Syncronizes the communication handler
  void Sync();

 private:
  std::weak_ptr<Context> context_;
  LoggerPtr logger_;
  std::string handler_info_;
  std::thread sender_thread_, receiver_thread_;
  std::unique_ptr<ENCRYPTO::LockedQueue<std::vector<std::uint8_t>>> lqueue_receive_;
  std::unique_ptr<ENCRYPTO::LockedQueue<std::vector<std::uint8_t>>> lqueue_send_;
  std::atomic<bool> continue_communication_ = true;
  std::atomic<bool> received_termination_message_ = false, sent_termination_message_ = false;
  std::size_t bytes_sent_ = 0, bytes_received_ = 0;

  void ReceivedTerminationMessage() { received_termination_message_ = true; }

  void SentTerminationMessage() { sent_termination_message_ = true; }

  void ActAsSender();

  void ActAsReceiver();

  std::uint32_t ParseHeader();

  std::vector<std::uint8_t> ParseBody(std::uint32_t size);
};

using HandlerPtr = std::shared_ptr<Handler>;
}  // namespace Communication
}  // namespace MOTION