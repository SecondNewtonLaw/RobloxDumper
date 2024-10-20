//
// Created by Dottik on 20/10/2024.
//

#include "VmShuffle7.hpp"

#include "Analysis/Disassembler.hpp"

namespace RobloxDumper::AnalysisTasks::VmShuffles {
    std::shared_ptr<VMShuffleResult> VMShuffle7::Analyse(RobloxDumper::DumperState &dumperState) {
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
         */
        std::map<std::string_view, std::string> vmShuffle7{};
        // __eq guarantees order due to an optimization called fasttm, lmao, thank u luau devs, whom on their path to speed, forgor about roblox security, oh yes!!!
        for (int i = 0; i < 8; i++) {
            vmShuffle7[((const char **) eventNames.value())[i]] = std::format("a{}", i + 1);
        }

        return std::make_shared<VMShuffleResult>(
            true, std::map<std::string, std::vector<MapInfo> >{
                {
                    "VMShuffle7", {
                        {"a1", vmShuffle7["__index"]},
                        {"a2", vmShuffle7["__newindex"]},
                        {"a3", vmShuffle7["__mode"]},
                        {"a4", vmShuffle7["__namecall"]},
                        {"a5", vmShuffle7["__call"]},
                        {"a6", vmShuffle7["__iter"]},
                        {"a7", vmShuffle7["__len"]}
                    }
                }
            }
        );
    }
}
