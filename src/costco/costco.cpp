#include <cmath>
#include <fstream>
#include <iostream>
#include <string>
#include <random>
#include <regex>
#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include "base/party.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/typedefs.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/run_time_statistics.h"

namespace mo = encrypto::motion;
namespace program_options = boost::program_options;

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
      //   ("parties", program_options::value<std::vector<std::string>>()->default_value({ "0,127.0.0.1,23000", "1,127.0.0.1,23001" }), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("role,r", program_options::value<std::size_t>(), "Role: 0/1")
      ("circuit-file,c", program_options::value<std::string>(), "circuit file")
      ("num-paral,n", program_options::value<uint32_t>()->default_value((uint32_t)1), "Number of parallel operation elements")
      ("num-round,i", program_options::value<uint32_t>()->default_value((uint32_t)10), "Number of rounds")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("circuit-protocol,m", program_options::value<std::size_t>()->default_value((std::size_t)1), "Circuit protocol 0=ARITH, 1=BOOL, 2=YAO, default: 0")
      ("online-after-setup", program_options::value<bool>()->default_value(true), "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)");
  program_options::variables_map user_options;
  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);
  if (help) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, std::vector<bool>>({}, std::vector<bool>{true, true});
  }
  if (!user_options.count("role")) 
    throw std::runtime_error("role (0/1) is not set but required");
  if (!user_options.count("circuit-file")) 
    throw std::runtime_error("circuit file is not set but required");
  std::string circuit_fpath = user_options["circuit-file"].as<std::string>();
  FILE *file = fopen(circuit_fpath.c_str(), "r");
  if (file == nullptr)
    throw std::runtime_error("circuit file does not exist");
  if (user_options.count("parties")) {
    const std::vector<std::string> other_parties{user_options["parties"].as<std::vector<std::string>>()};
    if (other_parties.size() < 2)
      throw std::runtime_error(fmt::format("Incorrect number of parties {}", other_parties.size()));
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
  const auto my_id{user_options["role"].as<std::size_t>()};
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

mo::ShareWrapper CreateShare(mo::PartyPointer& party, std::size_t protocol, uint32_t input, uint32_t party_id) {
  mo::ShareWrapper ret_share;
  if(protocol == (std::size_t)0){
    ret_share = mo::ShareWrapper(party->In<mo::MpcProtocol::kArithmeticGmw>(input, party_id));
  } else if(protocol == (std::size_t)1){
    ret_share = mo::ShareWrapper(party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(input), party_id));
  } else if(protocol == (std::size_t)2){
    ret_share = mo::ShareWrapper(party->In<mo::MpcProtocol::kBmr>(mo::ToInput(input), party_id));
  } else {
    throw std::invalid_argument("Invalid MPC protocol");
  }
  return ret_share;
}

uint32_t EvaluateCircuit(mo::PartyPointer& party, std::string circ_file_name, std::size_t role, std::size_t protocol, uint32_t nround, uint32_t nparal) {
    // start
    // read circuit file
    std::vector<std::string> gates;
	std::map<std::string, std::vector<std::string>> inputs;

	std::ifstream circ_file;
	circ_file.open(circ_file_name);
	std::string line;
	std::vector<std::string> tokens;
	while (std::getline(circ_file, line)) {
		if (boost::starts_with(line, "#")) {
			continue;
		}
		boost::split(tokens, line, [](char c){return c == ' ';});
		auto it = tokens.begin();
		std::string curr_node = *it;
		// std::cout << "curr_node: " << curr_node << std::endl;
		gates.push_back(curr_node);
		it++;
		for (it; it != tokens.end(); it++){
			inputs[*it].push_back(curr_node);
			// std::cout << "*it: " << *it << std::endl;
		}
        // inputs["ADD_3"] = ["ADD_2", "INPUT0_0"]
        // inputs["ADD_2"] = ["INPUT0_0", "INPUT1_1"]
		// std::cout << "***end loop***" << std::endl << std::endl;
		tokens.clear();
	}
	circ_file.close();

    // generate circuit
    std::map<std::string, mo::ShareWrapper> output_shares; // all gates that have output? output_shares["INPUT0_0"] -> INPUT0_0's output share
	std::vector<mo::ShareWrapper> outputs;
    srand(12345);
    for (std::string g : gates) {
        std::string g_type = g.substr(0, g.find("_")); // g = "INPUT0_0"
        std::vector<std::string> input_gates = inputs[g]; // inputs["ADD_2"] = ["INPUT0_0", "INPUT1_1"]
        if (g_type == "INPUT0") {
            //uint32_t val = rand();
            uint32_t val = 1;
            output_shares[g] = CreateShare(party, protocol, val, (uint32_t)0);
        } else if (g_type == "INPUT1") {
            //uint32_t val = rand();
            uint32_t val = 1;
            output_shares[g] = CreateShare(party, protocol, val, (uint32_t)1);
        } else if (g_type == "A2Y" || g_type == "B2Y") {
            mo::ShareWrapper input = output_shares[input_gates[0]];
            output_shares[g] = input.Convert<mo::MpcProtocol::kBmr>();
        } else if (g_type == "A2B" || g_type == "Y2B") {
            mo::ShareWrapper input = output_shares[input_gates[0]];
            output_shares[g] = input.Convert<mo::MpcProtocol::kBooleanGmw>();
        } else if (g_type == "B2A" || g_type == "Y2A") {
            mo::ShareWrapper input = output_shares[input_gates[0]];
            output_shares[g] = input.Convert<mo::MpcProtocol::kArithmeticGmw>();
        } else if (g_type == "OUTPUT") {
            mo::ShareWrapper input = output_shares[input_gates[0]];
            std::string input_t = input_gates[0].substr(0, input_gates[0].find("_"));
            output_shares[g] = input.Out();
            outputs.push_back(output_shares[g]);
        } else {
            // if g = "ADD_2"
            // input_gates = inputs["ADD_2"] = ["INPUT0_0", "INPUT1_1"]
            // output_shares = {"INPUT0_0": ...; "INPUT1_1": ...}
            mo::ShareWrapper input1 = output_shares[input_gates[0]]; //input1 = output_shares["INPUT0_0"]
            mo::ShareWrapper input2 = output_shares[input_gates[1]]; //input2 = output_shares["INPUT1_1"]
            if (g_type == "MUL") {
                output_shares[g] = input1 * input2;
            } else if (g_type == "ADD") {
                output_shares[g] = input1 + input2;
            } else if (g_type == "SUB") {
                output_shares[g] = input1 - input2;
            } else if (g_type == "DIV") {
                output_shares[g] = input1 / input2;
            } else if (g_type == "AND") {
                output_shares[g] = input1 & input2;
            } else if (g_type == "OR") {
                output_shares[g] = input1 | input2;
            } else if (g_type == "XOR") {
                output_shares[g] = input1 ^ input2;
            } else if (g_type == "GT") {
                output_shares[g] = input1 > input2;
            } else if (g_type == "LT") {
                output_shares[g] = input2 > input1;
            } else if (g_type == "GE") {
                mo::ShareWrapper temp = input2 > input1;
                output_shares[g] = ~temp;
            } else if (g_type == "LE") {
                mo::ShareWrapper temp = input1 > input2;
                output_shares[g] = ~temp;
            } else if (g_type == "EQ") {
                output_shares[g] = input1 == input2;
            } else if (g_type == "NE") {
                output_shares[g] = ~(input1 == input2);
            } 
            // else if (g_type == "MUX") {
            //     // do circuit files include 'MUX'?
            // }  
        }
    }
    // run circuit
    party->Run();
    party->Finish();
    mo::AccumulatedRunTimeStatistics accumulated_statistics;
    mo::AccumulatedCommunicationStatistics accumulated_communication_statistics;
    const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
    accumulated_statistics.Add(statistics.front());
    auto communication_statistics = party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
    std::cout << "output: " << std::endl;
    for(mo::SecureUnsignedInteger x : outputs){
        std::cout << x.As<std::uint32_t>() << std::endl;
    }
    std::cout << mo::PrintStatistics(fmt::format("op_name"), accumulated_statistics, accumulated_communication_statistics);
    
    output_shares.clear();
	outputs.clear();
    // end
	return 0;
}

int main(int ac, char* av[]) {
  try {
    auto [user_options, flag] = ParseProgramOptions(ac, av);
    if (flag[0]) return EXIT_SUCCESS;
    const auto role{user_options["role"].as<std::size_t>()};
    const auto circuit_file{user_options["circuit-file"].as<std::string>()};
    const auto protocol{user_options["circuit-protocol"].as<std::size_t>()};
    const auto nround{user_options["num-round"].as<uint32_t>()};
    const auto nparal{user_options["num-paral"].as<uint32_t>()};
    // all inputs (in input gate) default to "1", no need for user inputs
    for (uint32_t r = 0; r < nround; r++) {
        encrypto::motion::PartyPointer party{CreateParty(user_options)};
        EvaluateCircuit(party, circuit_file, role, protocol, nround, nparal);
        std::cout << "&party: " << &party << std::endl;
        // delete &party;
    }
    // delete party;
  } catch (std::runtime_error& e) {
    std::cerr << e.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}