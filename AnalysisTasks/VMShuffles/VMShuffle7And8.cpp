//
// Created by Dottik on 20/10/2024.
//

#include "VMShuffle7And8.hpp"

#include "Analysis/Disassembler.hpp"

namespace RobloxDumper::AnalysisTasks::VmShuffles {
    std::shared_ptr<VMShuffleResult> VMShuffle7And8::Analyse(RobloxDumper::DumperState &dumperState) {
        auto robloxDumperDisassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();
        auto lpluaGArithError = dumperState.FunctionMap.at("luaG_aritherror");

        auto possibleInstructions = robloxDumperDisassembler->GetInstructions(lpluaGArithError,
                                                                              reinterpret_cast<void *>(
                                                                                  reinterpret_cast<std::uintptr_t>(
                                                                                      lpluaGArithError) + 0x4C),
                                                                              true);

        if (!possibleInstructions.has_value())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        const auto disassembledChunk = std::move(possibleInstructions.value());

        const auto targetInsn = disassembledChunk->GetInstructionWhichMatches("lea", "r8, [rip +", true);

        if (!targetInsn.has_value())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        const auto leaEventNamesTable = targetInsn.value();

        const auto eventNames = robloxDumperDisassembler->TranslateRelativeLeaIntoRuntimeAddress(leaEventNamesTable);

        if (!eventNames.has_value())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        /*
            "__index",
            "__newindex",
            "__mode",
            "__namecall",
            "__call",
            "__iter",
            "__len",
            // __eq guarantees order due to an optimization called fasttm, lmao, thank u luau devs, whom on their path to speed, forgor about roblox security, oh yes!!!
        */
        auto vmShuffle7 = std::map<std::string, std::string>{
            {"__index", "a1"}, {"__newindex", "a2"}, {"__mode", "a3"}, {"__namecall", "a4"}, {"__call", "a5"},
            {"__iter", "a6"}, {"__len", "a7"}
        };

        /*
            "__add",
            "__sub",
            "__mul",
            "__div",
            "__idiv",
            "__mod",
            "__pow",
            "__unm",
         */
        auto vmShuffle8 = std::map<std::string, std::string>{
            {"__add", "a1"},
            {"__sub", "a2"},
            {"__mul", "a3"},
            {"__div", "a4"},
            {"__idiv", "a5"},
            {"__mod", "a6"},
            {"__pow", "a7"},
            {"__unm", "a8"},
        };

        auto eventNamesStringArray = (const char **) eventNames.value();


        return std::make_shared<VMShuffleResult>(
            true, std::map<std::string, std::vector<MapInfo> >{
                {
                    "VMShuffle7", {
                        {"a1", vmShuffle7[eventNamesStringArray[0]]},
                        {"a2", vmShuffle7[eventNamesStringArray[1]]},
                        {"a3", vmShuffle7[eventNamesStringArray[2]]},
                        {"a4", vmShuffle7[eventNamesStringArray[3]]},
                        {"a5", vmShuffle7[eventNamesStringArray[4]]},
                        {"a6", vmShuffle7[eventNamesStringArray[5]]},
                        {"a7", vmShuffle7[eventNamesStringArray[6]]}
                    }
                },
                {
                    "VMShuffle8", {
                        {"a1", vmShuffle8[eventNamesStringArray[8]]},
                        {"a2", vmShuffle8[eventNamesStringArray[9]]},
                        {"a3", vmShuffle8[eventNamesStringArray[10]]},
                        {"a4", vmShuffle8[eventNamesStringArray[11]]},
                        {"a5", vmShuffle8[eventNamesStringArray[12]]},
                        {"a6", vmShuffle8[eventNamesStringArray[13]]},
                        {"a7", vmShuffle8[eventNamesStringArray[14]]},
                        {"a8", vmShuffle8[eventNamesStringArray[15]]}
                    }
                }
            }
        );
    }
}
