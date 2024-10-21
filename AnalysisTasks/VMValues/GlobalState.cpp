//
// Created by Dottik on 21/10/2024.
//

#include "GlobalState.hpp"

#include "Analysis/Disassembler.hpp"

std::shared_ptr<RobloxDumper::AnalysisTasks::VmValues::VMValueResult>
RobloxDumper::AnalysisTasks::VmValues::GlobalState::Analyse(RobloxDumper::DumperState &dumperState) {
    const auto robloxDumperDisassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();

    if (!dumperState.FunctionMap.contains("luaC_step"))
        return std::make_shared<VMValueResult>("GlobalState",
                                               ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::UNKNOWN);

    const auto luaCStep = dumperState.FunctionMap.at("luaC_step");

    auto encryption = ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::UNKNOWN;

    while (true) {
        auto possibleDisassembly = robloxDumperDisassembler->GetInstructions(luaCStep,
                                                                             reinterpret_cast<void *>(
                                                                                 reinterpret_cast<std::uintptr_t>(
                                                                                     luaCStep) + 0x2C), true);

        if (!possibleDisassembly.has_value())
            return std::make_shared<VMValueResult>("GlobalState",
                                                   ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::UNKNOWN);

        const auto disassembly = std::move(possibleDisassembly.value());

        const auto possibleInsn = disassembly->GetInstructionWhichMatches(nullptr, "rbx, qword ptr [rbx]", true);

        if (!possibleInsn.has_value()) {
            // The previous case will cover us for three of the cases, but will not cover us for a variation of VMValue SUB, in which case the order of the rbx, [rbx] will be reverted into -> [rbx], rbx

            const auto possibleSubInsn = disassembly->GetInstructionWhichMatches("sub", "qword ptr [rbx], rbx", true);

            if (!possibleSubInsn.has_value())
                return std::make_shared<VMValueResult>("GlobalState",
                                                       ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::UNKNOWN);

            encryption = ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::SUB_1;
            break;
        }

        auto insn = possibleInsn.value();

        if (insn.id == ::x86_insn::X86_INS_XOR)
            encryption = ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::XOR;
        else if (insn.id == ::x86_insn::X86_INS_AND)
            encryption = ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::ADD;
        else if (insn.id == ::x86_insn::X86_INS_SUB)
            encryption = ::RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::SUB_0;

        break;
    }

    return std::make_shared<VMValueResult>("GlobalState", encryption);
}
