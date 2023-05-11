// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include <cmath>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/party.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/typedefs.h"

namespace program_options = boost::program_options;

const std::regex kPartyArgumentRegex("([012]),([^,]+),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& party_argument) {
  // other party's id, host address, and port
  return std::regex_match(party_argument, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_argument) {
  std::smatch match;
  std::regex_match(party_argument, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

// <variables map, (help flag, print_output flag)>
std::pair<program_options::variables_map, std::vector<bool>> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view kConfigFileMessage =
      "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;
  bool print, help, print_output;
  program_options::options_description description("Allowed options");
  // clang-format off
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "(other party id, host, port, my role), e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("protocol", program_options::value<std::string>()->default_value("a"), "MPC protocol")
      ("online-after-setup", program_options::value<bool>()->default_value(true), "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)")
      ("print-output", program_options::bool_switch(&print_output)->default_value(false), "print result")
      ("num-test,n", program_options::value<std::size_t>()->default_value(1), "number of tests")
      ("num-paral,m", program_options::value<std::size_t>()->default_value(1), "number of parallel operations")
      ("bit-len,b", program_options::value<std::uint32_t>()->default_value(32), "bit length")
      ("rand-seed,k", program_options::value<std::uint32_t>()->default_value(1), "random seed");

  // clang-format on

  program_options::variables_map user_options;

  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);

  // argument help or no arguments (at least a configuration file is expected)
  if (help) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, std::vector<bool>>(
        {}, std::vector<bool>{true, print_output});
  }

  // read configuration file
  if (user_options.count("configuration-file")) {
    std::ifstream user_options_file(user_options["configuration-file"].as<std::string>().c_str());
    program_options::store(program_options::parse_config_file(user_options_file, description), user_options);
    program_options::notify(user_options);
  }

  // print parsed parameters
  if (user_options.count("my-id")) {
    if (print) std::cout << "My id " << user_options["my-id"].as<std::size_t>() << std::endl;
  } else
    throw std::runtime_error("My id is not set but required");

  if (user_options.count("parties")) {
    const std::vector<std::string> other_parties{user_options["parties"].as<std::vector<std::string>>()};
    if (other_parties.size() != 2)
      throw std::runtime_error(fmt::format("Default to be 2 parties (TODO: extend to more)", other_parties.size()));
    std::string parties("Other parties: ");
    for (auto& party : other_parties) {
      if (CheckPartyArgumentSyntax(party)) {
        if (print) parties.append(" " + party);
      } else {
        throw std::runtime_error(fmt::format("Incorrect party argument syntax for party {}", party));
      }
    }
    if (print) std::cout << parties << std::endl;
  } else
    throw std::runtime_error("Other parties' information is not set but required");

  if (print) {
    std::cout << "MPC Protocol: " << user_options["protocol"].as<std::string>() << std::endl;
  }
  return std::make_pair(user_options, std::vector<bool>{help, print_output});
}

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options) {
  const auto parties_string{user_options["parties"].as<const std::vector<std::string>>()};
  const auto number_of_parties{parties_string.size()};
  const auto my_id{user_options["my-id"].as<std::size_t>()};
  if (my_id >= number_of_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
        my_id, number_of_parties));
  }

  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);

  for (const auto& party_string : parties_string) {
    const auto [party_id, host, port] = ParsePartyArgument(party_string);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(
          fmt::format("Party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }
  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));
  auto configuration = party->GetConfiguration();
  // disable logging if the corresponding flag was set
  const auto logging{!user_options.count("disable-logging")};
  configuration->SetLoggingEnabled(logging);
  configuration->SetOnlineAfterSetup(user_options["online-after-setup"].as<bool>());
  return party;
}


mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer& party, std::string protocol, std::vector<uint32_t> party_input, int party_id) {
  std::vector<mo::SecureUnsignedInteger> output(party_input.size());
	std::vector<mo::ShareWrapper> p1(party_input.size());
  std::vector<mo::ShareWrapper> p2(party_input.size());
	for(int i = 0; i < party_input.size(); i++) {
    p1[i] = CreateShare(party, protocol, party_input[i], party_id);
    p2[i] = CreateShare(party, protocol, (uint32_t)0, party_id); //dummy_input to other party
	}
	for(int i = 0; i < party_input.size(); i++) {
    mo::ShareWrapper op_result = CreateOPCircuit(p1[i], p2[i], party, protocol);
    output.push_back(op_result.Out());
	}
  party->Run();
	party->Finish();
  std::cout << "output: " << std::endl;
  for(mo::SecureUnsignedInteger x : output){
      std::cout << x.As<std::uint32_t>() << ", ";
  }
  std::cout << std::endl;
	const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
	return statistics.front();
}

mo::ShareWrapper CreateShare(mo::PartyPointer& party, std::string protocol, uint32_t input, uint32_t party_id) {
  mo::ShareWrapper ret_share;
  if(protocol == "a"){
    ret_share = mo::ShareWrapper(party->In<mo::MpcProtocol::kArithmeticGmw>(input, party_id));
  } else if(protocol == "b" || protocol == "default"){
    ret_share = mo::ShareWrapper(party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(input), party_id));
  } else if(protocol == "y"){
    ret_share = mo::ShareWrapper(party->In<mo::MpcProtocol::kBmr>(mo::ToInput(input), party_id));
  } else {
    throw std::invalid_argument("Invalid MPC protocol");
  }
  return ret_share;
}

mo::ShareWrapper ConvertShare(mo::ShareWrapper sw, std::string protocol){
  mo::ShareWrapper ret_share;
  if(protocol == "b2a" || protocol == "y2a"){
    ret_share = sw.Convert<mo::MpcProtocol::kArithmeticGmw>();
  } else if(protocol == "a2b" || protocol == "y2b"){
    ret_share = sw.Convert<mo::MpcProtocol::kBooleanGmw>();
  } else if(protocol == "a2y" || protocol == "b2y"){
    ret_share = sw.Convert<mo::MpcProtocol::kBmr>();
  } else {
    throw std::invalid_argument("Invalid Conversion");
  }
  return ret_share;
}

int main(int ac, char* av[]) {
  try {
    auto [user_options, flag] = ParseProgramOptions(ac, av);
    // if help flag is set - print allowed command line arguments and exit
    if (flag[0]) return EXIT_SUCCESS;

    encrypto::motion::MpcProtocol protocol;
    const std::string protocol_string{user_options["protocol"].as<std::string>()};
    std::map<std::string, encrypto::motion::MpcProtocol> protocol_conversion{
        {"a", encrypto::motion::MpcProtocol::kArithmeticGmw},
        {"b", encrypto::motion::MpcProtocol::kBooleanGmw},
        {"y", encrypto::motion::MpcProtocol::kBmr},
    };
    bool print_output = flag[1];
    std::uint32_t input_command_line;
    std::string input_file_path;

    std::size_t party_id = user_options["my-id"].as<std::size_t>();
    std::size_t num_paral = user_options["num-paral"].as<std::size_t>();
    std::size_t num_test = user_options["num-test"].as<std::size_t>();
    std::cout << "Num of parallel operations = " << num_paral << std::endl; 
    std::uint32_t bitlen = user_options["bit-len"].as<std::uint32_t>();

    std::vector<uint32_t> party_input(num_paral);

    srand(user_options["rand-seed"].as<std::uint32_t>());
    const std::uint32_t kTruncate = bitlen;
    for(std::size_t i = 0; i < party_input.size(); i++) {
      party_input[i] = rand() % kTruncate;
    }
    std::cout << "party_input[1]: " << party_input[1] << std::endl;

    encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
    encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;

    // establish communication channels with other parties

    auto protocol_iterator = protocol_conversion.find(protocol_string);
    if (protocol_iterator != protocol_conversion.end()) {
      protocol = protocol_iterator->second;
      encrypto::motion::PartyPointer party{CreateParty(user_options)};
      auto statistics = EvaluateProtocol(party, protocol, num_paral, party_input, (int)party_id);
      accumulated_statistics.Add(statistics);
      auto communication_statistics = party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
      accumulated_communication_statistics.Add(communication_statistics);
    } else { 
      throw std::invalid_argument("Invalid MPC protocol");
    }

    std::cout << encrypto::motion::PrintStatistics(fmt::format("op_name", protocol_string),
                                                   accumulated_statistics,
                                                   accumulated_communication_statistics);

  } catch (std::runtime_error& e) {
    std::cerr << e.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}