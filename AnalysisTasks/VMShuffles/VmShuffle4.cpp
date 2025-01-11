//
// Created by Dottik on 2/11/2024.
//

#include "VmShuffle4.hpp"

#include "Analysis/Disassembler.hpp"

namespace RobloxDumper::AnalysisTasks {
    namespace VMShuffles {
    } // VMShuffles
    std::shared_ptr<VmShuffles::VMShuffleResult>
    VmShuffles::VMShuffle4::Analyse(RobloxDumper::DumperState &dumperState) {
        auto robloxDumperDisassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();
        auto vlpDumpTable = dumperState.XrefMap.at("dumptable");

        if (vlpDumpTable.empty())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        auto lpDumpTable = *vlpDumpTable.data();

        auto insns = robloxDumperDisassembler->GetInstructions(
            reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(lpDumpTable) + 0x10), reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(lpDumpTable) - 0x10), true);

        if (!insns.has_value())
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        auto disasm = std::move(insns.value());

        // Cannot find Node.
        if (!disasm->ContainsInstruction("lea", "rdi, [rip +", true))
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        auto insn = disasm->GetInstructionWhichMatches("lea", "rdi, [rip +", true).value();

        // Table->node encryption
        // if (!disasm->ContainsInstruction(nullptr, "r8, r15", true))
        //     return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});
    }
}
