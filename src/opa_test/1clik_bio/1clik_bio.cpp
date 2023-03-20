#include <cmath>
#include <fstream>
#include <iostream>
#include <string>
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
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/run_time_statistics.h"
namespace mo = encrypto::motion;
namespace program_options = boost::program_options;
bool CheckPartyArgumentSyntax(const std::string& party_argument);
std::pair<program_options::variables_map, std::vector<bool>> ParseProgramOptions(int ac, char* av[]);
encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options);
mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer& party, std::vector<std::vector<uint32_t>> input);
mo::ShareWrapper CreateShare(mo::PartyPointer& party, std::string protocol, uint32_t input, uint32_t party_id);
mo::ShareWrapper ConvertShare(mo::ShareWrapper sw, std::string protocol);

int main(int ac, char* av[]) {
  try {
    auto [user_options, flag] = ParseProgramOptions(ac, av);
    if (flag[0]) return EXIT_SUCCESS;
    const auto my_id{user_options["my-id"].as<std::size_t>()};
    const uint32_t num_input_arr{user_options["num-input-arr"].as<uint32_t>()};
    const std::vector<std::string> input_str{user_options["input"].as<std::vector<std::string>>()};
    std::vector<std::vector<uint32_t>> input(num_input_arr);
    int index = 0;
    for(std::string s : input_str){
      if(s == ","){
        index++;
        continue;
      }
      input[index].push_back(static_cast<uint32_t>(std::stoul(s,nullptr,0)));
    }
    // print input
    std::cout << "input: " << std::endl;
    for(std::vector<uint32_t> input_arr : input){
      for(uint32_t x : input_arr){
        std::cout << x << " ";
      }
      std::cout << std::endl;
    }
    // finish print
    encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
    encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
    encrypto::motion::PartyPointer party{CreateParty(user_options)};
    auto statistics = EvaluateProtocol(party, input);
    accumulated_statistics.Add(statistics);
    auto communication_statistics = party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
    std::cout << encrypto::motion::PrintStatistics(fmt::format("op_name"), accumulated_statistics, accumulated_communication_statistics);
  } catch (std::runtime_error& e) {
    std::cerr << e.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

const std::regex kPartyArgumentRegex("([012]),([^,]+),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& party_argument) {
  return std::regex_match(party_argument, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(const std::string& party_argument) {
  std::smatch match;
  std::regex_match(party_argument, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

std::pair<program_options::variables_map, std::vector<bool>> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  bool help;
  program_options::options_description description("Allowed options");
  
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "(other party id, host, port, my role), e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("protocol", program_options::value<std::string>()->default_value("b"), "MPC protocol")
      ("num-input-arr,n", program_options::value<uint32_t>(), "number of input arrays")
      ("input,i", program_options::value<std::vector<std::string>>()->multitoken(), "input array, separate arrays with comma")
      ("online-after-setup", program_options::value<bool>()->default_value(true), "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)");
  program_options::variables_map user_options;
  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);
  if (help) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, std::vector<bool>>({}, std::vector<bool>{true, true});
  }
  if (!user_options.count("my-id")) 
    throw std::runtime_error("My id is not set but required");
  if (user_options.count("parties")) {
    const std::vector<std::string> other_parties{user_options["parties"].as<std::vector<std::string>>()};
    if (other_parties.size() != 2 && (user_options.count("input") || user_options.count("input-file")))
      throw std::runtime_error(fmt::format("Incorrect number of parties {} for the chosen input type", other_parties.size()));
    std::string parties("Other parties: ");
    for (auto& party : other_parties) {
      if (!CheckPartyArgumentSyntax(party)) 
        throw std::runtime_error(fmt::format("Incorrect party argument syntax for party {}", party));
    }
  } else throw std::runtime_error("Other parties' information is not set but required");
  return std::make_pair(user_options, std::vector<bool>{help, true});
}

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options) {
  const auto parties_string{user_options["parties"].as<const std::vector<std::string>>()};
  const auto number_of_parties{parties_string.size()};
  const auto my_id{user_options["my-id"].as<std::size_t>()};
  if (my_id >= number_of_parties) {
    throw std::runtime_error(fmt::format("My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}", my_id, number_of_parties));
  }
  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);
  for (const auto& party_string : parties_string) {
    const auto [party_id, host, port] = ParsePartyArgument(party_string);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(fmt::format("Party's id needs to be in the range [0, #parties - 1], current id ", "is {} and #parties is {}", party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }
  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));
  auto configuration = party->GetConfiguration();
  configuration->SetOnlineAfterSetup(user_options["online-after-setup"].as<bool>());
  return party;
}

//playground.cpp from here
mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer& party, std::vector<std::vector<uint32_t>> input) {
    std::vector<mo::SecureUnsignedInteger> output;
	std::vector<std::vector<mo::ShareWrapper>> r1(4);
	for(int i = 0; i < 4; i++){
		r1[i] = std::vector<mo::ShareWrapper> (4);
	}
	int i23 = 0;
	for(; i23 < 4;) {
		int i24_1 = 0;
		for(; i24_1 < 4;) {
			int ti20 = i23 * 4;
			int ti21 = ti20 + i24_1;
			mo::ShareWrapper ti22 = CreateShare(party, "y", input[0][ti21], 0);
			r1[i23][i24_1] = ti22;
			i24_1 = i24_1 + 1;
		}
		i23 = i23 + 1;
	}
	std::vector<mo::ShareWrapper> r9(4);
	int i25 = 0;
	for(; i25 < 4;) {
		mo::ShareWrapper ti19 = CreateShare(party, "y", input[1][i25], 1);
		r9[i25] = ti19;
		i25 = i25 + 1;
	}
	std::vector<mo::ShareWrapper> r10(4);
	std::vector<mo::ShareWrapper> r2(4);
	int i26 = 0;
	for(; i26 < 4;) {
		mo::ShareWrapper ti18 = CreateShare(party, "y", input[2][i26], 0);
		r2[i26] = ti18;
		i26 = i26 + 1;
	}
	int i27 = 0;
	for(; i27 < 4;) {
		mo::ShareWrapper ti6 = r1[i27][0];
		mo::ShareWrapper ti5 = r9[0];
		mo::ShareWrapper ti10 = ti6 - ti5;
		mo::ShareWrapper ti8 = r1[i27][0];
		mo::ShareWrapper ti7 = r9[0];
		mo::ShareWrapper ti9 = ti8 - ti7;
		mo::ShareWrapper i28_1 = ti10 * ti9;
		int i29_1 = 1;
		for(; i29_1 < 4;) {
			mo::ShareWrapper ti12 = r1[i27][i29_1];
			mo::ShareWrapper ti11 = r9[i29_1];
			mo::ShareWrapper ti16 = ti12 - ti11;
			mo::ShareWrapper ti14 = r1[i27][i29_1];
			mo::ShareWrapper ti13 = r9[i29_1];
			mo::ShareWrapper ti15 = ti14 - ti13;
			mo::ShareWrapper ti17 = ti16 * ti15;
			i28_1 = i28_1 + ti17;
			i29_1 = i29_1 + 1;
		}
		r10[i27] = i28_1;
		i27 = i27 + 1;
	}
	mo::ShareWrapper i30 = r10[0];
	mo::ShareWrapper i31 = r2[0];
	int i32 = 1;
	for(; i32 < 4;) {
		mo::ShareWrapper i2 = i30;
		mo::ShareWrapper i3 = i31;
		mo::ShareWrapper ti4 = r10[i32];
		mo::ShareWrapper j68_gt = i30 > ti4;
		mo::ShareWrapper j68 = ~j68_gt;
		mo::ShareWrapper i30_2 = r10[i32];
		mo::ShareWrapper i31_2 = r2[i32];
		mo::ShareWrapper i30_3 = i2;
		mo::ShareWrapper i31_3 = i3;
		i31 = j68.Mux(i31_3, i31_2);
		i30 = j68.Mux(i30_3, i30_2);
		i32 = i32 + 1;
	}
	output.push_back(i31.Out());
	output.push_back(i30.Out());
    party->Run();
	party->Finish();
    std::cout << "output: " << std::endl;
    for(mo::SecureUnsignedInteger x : output){
        std::cout << x.As<std::uint32_t>() << std::endl;
    }
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
