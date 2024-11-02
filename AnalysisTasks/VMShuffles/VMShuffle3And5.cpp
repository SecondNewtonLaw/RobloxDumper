//
// Created by Dottik on 20/10/2024.
//

#include "VMShuffle3And5.hpp"

#include "Analysis/Disassembler.hpp"

namespace RobloxDumper::AnalysisTasks::VmShuffles {
    std::shared_ptr<VMShuffleResult> VMShuffle3And5::Analyse(RobloxDumper::DumperState &dumperState) {
        auto robloxDumperDisassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();
        auto lpLuaType = dumperState.FunctionMap.at("lua_type");

        auto possibleInstructions = robloxDumperDisassembler->GetInstructions(lpLuaType,
                                                                              reinterpret_cast<void *>(
                                                                                  reinterpret_cast<std::uintptr_t>(
                                                                                      lpLuaType) + 0x1D),
                                                                              true);

        if (!possibleInstructions.has_value())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        const auto instructions = std::move(possibleInstructions.value());

        const auto loadTableAddress = instructions->GetInstructionWhichMatches("lea", "rsi, [rip +", true);

        if (!loadTableAddress.has_value())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        const auto loadTableInstruction = loadTableAddress.value();
        const auto possibleTypeTable = robloxDumperDisassembler->TranslateRelativeLeaIntoRuntimeAddress(
            loadTableInstruction);

        if (!possibleTypeTable.has_value())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        const auto typeTable = (const char **) static_cast<const char *>(possibleTypeTable.value());

        /*
         *  To dump VMShuffle 3 and 5 we must use lua_type, and read the luaT_typenames table.
         *  This allows us to, well, get whatever the fuck we are after. But this requires us to separate the typenames into sections.
         *
         *  Section 0
         *      - nil
         *      - boolean
         *  Section 1 (VMShuffle 3)
         *      - userdata
         *      - number
         *      - vector
         *  Section 2
         *      - string
         *  Section 3 (VMShuffle 5)
         *      - table
         *      - function
         *      - userdata
         *      - thread
         *      - buffer
         */
        std::map<std::string, std::vector<MapInfo> > shuffleMap{};

        auto tableOrder = std::vector<const char *>{
            typeTable[0], // nil
            typeTable[1], // boolean

            typeTable[2], // shuffled (should be userdata)
            typeTable[3], // shuffled (should be number)
            typeTable[4], // shuffled (should be vector)

            typeTable[5], // string

            typeTable[6], // shuffled (should be table)
            typeTable[7], // shuffled (should be function)
            typeTable[8], // shuffled (should be userdata)
            typeTable[9], // shuffled (should be thread)
            typeTable[10] // shuffled (should be buffer)
        };

        auto vmShuffle3 = std::map<std::string, std::string>{
            {"userdata", "a1"}, {"number", "a2"}, {"vector", "a3"}
        };

        auto vmShuffle5 = std::map<std::string, std::string>{
            {"table", "a1"}, {"function", "a2"}, {"userdata", "a3"}, {"thread", "a4"}, {"buffer", "a5"}
        };

        shuffleMap["VMShuffle3"] = {
            {"a1", vmShuffle3[tableOrder[2]]},
            {"a2", vmShuffle3[tableOrder[3]]},
            {"a3", vmShuffle3[tableOrder[4]]},
        };
        shuffleMap["VMShuffle5"] = {
            {"a1", vmShuffle5[tableOrder[6]]},
            {"a2", vmShuffle5[tableOrder[7]]},
            {"a3", vmShuffle5[tableOrder[8]]},
            {"a4", vmShuffle5[tableOrder[9]]},
            {"a5", vmShuffle5[tableOrder[10]]},
        };

        return std::make_shared<VMShuffleResult>(true, shuffleMap);
    }
} // RobloxDumper::AnalysisTasks::VmShuffles
