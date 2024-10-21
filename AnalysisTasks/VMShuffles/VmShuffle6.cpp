//
// Created by Dottik on 21/10/2024.
//

#include "VmShuffle6.hpp"

#include <ranges>
#include <unordered_set>

#include "Analysis/XrefSearcher.hpp"

namespace RobloxDumper {
    std::shared_ptr<AnalysisTasks::VmShuffles::VMShuffleResult> AnalysisTasks::VmShuffles::VMShuffle6::Analyse(
        RobloxDumper::DumperState &dumperState) {
        const auto robloxDumperDisassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();

        if (!dumperState.FunctionMap.contains("RBX::ScriptContext::resumeWaitingThreads (Fragment)") || !dumperState.
            FunctionMap.contains("RBX::ScriptContext::checkRequirePermission") || !dumperState.FunctionMap.
            contains("luaC_step") || !dumperState.XrefMap.contains("Color3.fromHex"))
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

        const auto resumeWaitingThreads = dumperState.FunctionMap.at(
            "RBX::ScriptContext::resumeWaitingThreads (Fragment)");
        const auto requireCheck = dumperState.FunctionMap.at("RBX::ScriptContext::checkRequirePermission");
        const auto luaCStep = dumperState.FunctionMap.at("luaC_step");
        const auto color3FromHex = dumperState.XrefMap.at("Color3.fromHex").front();

        auto currentDisplacements = std::map<std::uintptr_t, std::string>{
        };
        auto correctDisplacements = std::map<std::string, std::uintptr_t>{
            {"L->top", 0x8}, // L->top               // COMPLETE
            {"L->base", 0x10}, // L->base             // COMPLETE
            {"L->global", 0x18}, // L->global           // COMPLETE
            {"L->ci", 0x20}, // L->ci               // COMPLETE
            {"L->stack_last", 0x28}, // L->stack_last       // COMPLETE
            {"L->stack", 0x30}, // L->stack            // --- ??? (WE DON'T NECESSARILY NEED ALL OF THEM!)
        };

        while (true) {
            auto possibleDisassembly = robloxDumperDisassembler->GetInstructions(
                color3FromHex, reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(color3FromHex) + 0x15), true);

            if (!possibleDisassembly.has_value())
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            auto disassembly = std::move(possibleDisassembly.value());

            /*
             *  This shuffle is fairly more complex, we must split our code to obtain the shuffle positions by first obtaining the position for the
             *  lua stack top and lua stack base, then we must resolve for part of the shuffle, being only two of them, and then resolve for the other missing four in other places.
             */

            auto possibleLoadTop = disassembly->GetInstructionWhichMatches("mov", "r8, qword ptr [rcx +", true);
            auto possibleLoadBase = disassembly->GetInstructionWhichMatches("mov", "rcx, qword ptr [rcx +", true);

            if (!possibleLoadBase.has_value() || !possibleLoadTop.has_value())
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            while (true) {
                // Resolving part of struct using lua top and lua base
                currentDisplacements[possibleLoadTop.value().detail->x86.operands[1].mem.disp] = "L->top";
                currentDisplacements[possibleLoadBase.value().detail->x86.operands[1].mem.disp] = "L->base";
                break;
            }
            break;
        }

        while (true) {
            auto possibleDisassembly = robloxDumperDisassembler->GetInstructions(luaCStep,
                reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(
                                             luaCStep) + 0x2C), true);

            if (!possibleDisassembly.has_value())
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            const auto disassembly = std::move(possibleDisassembly.value());

            const auto possibleInsn = disassembly->GetInstructionWhichMatches("lea", "rbx, [rcx +", true);

            if (!possibleInsn.has_value())
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            currentDisplacements[possibleInsn->detail->x86.operands[1].mem.disp] = "L->global";

            break;
        }

        while (true) {
            auto possibleDisassembly = robloxDumperDisassembler->GetInstructions(requireCheck,
                reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(
                                             requireCheck) + 0x45), true);

            if (!possibleDisassembly.has_value())
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            const auto disassembly = std::move(possibleDisassembly.value());

            auto loadCiInsn = disassembly->GetInstructionWhichMatches("mov", "rcx, qword ptr [r9 +", true);

            if (!loadCiInsn.has_value())
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            currentDisplacements[loadCiInsn.value().detail->x86.operands[1].mem.disp] = "L->ci";
            break;
        }

        while (true) {
            auto possibleDisassembly = robloxDumperDisassembler->GetInstructions(resumeWaitingThreads,
                reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(
                                             resumeWaitingThreads) + 0x45), true);

            if (!possibleDisassembly.has_value())
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            const auto disassembly = std::move(possibleDisassembly.value());

            /*
             *  If the signature match, then we are golly, we just need to obtain the call insn that comes next, that is everything we need.
             */

            for (const auto &insn: disassembly->GetInstructions()) {
                if (insn.id == ::x86_insn::X86_INS_CALL) {
                    // Call insn, redirects to our target, lua_checkstack, lua_checkstack references stack_last before reallocating the stack.
                    // This allows us to get the address to L->stack_last quite simply.
                    const auto lua_checkstack = reinterpret_cast<void *>(insn.detail->x86.operands[0].imm);

                    auto possibleDisassemblyOfCheckStack = robloxDumperDisassembler->GetInstructions(lua_checkstack,
                        reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(
                                                     lua_checkstack) + 0x5E), true);

                    if (!possibleDisassemblyOfCheckStack.has_value())
                        return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

                    auto checkStackDissassembly = std::move(possibleDisassemblyOfCheckStack.value());

                    auto loadStackLast = checkStackDissassembly->GetInstructionWhichMatches(
                        "mov", "rcx, qword ptr [rcx +", true);

                    if (!loadStackLast.has_value())
                        return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

                    currentDisplacements[loadStackLast.value().detail->x86.operands[1].mem.disp] = "L->stack_last";
                    break;
                }
            }

            auto found = false;
            for (const auto &displacement: currentDisplacements) {
                if (displacement.second == "L->stack_last")
                    found = true;
            }

            if (!found)
                return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});

            break;
        }

        /*
         *  Due to laziness we must bruteforce L->stack, which is within shuffle 6 regardless, we must check which displacement is not on our currently documented ones, and just push the correct one.
         */

        std::unordered_set<std::uintptr_t> displacements{};
        for (const auto &offsetDiff: currentDisplacements | std::views::keys)
            displacements.insert(offsetDiff);


        for (const auto &offs: correctDisplacements) {
            if (!displacements.contains(offs.second)) {
                // This is L->stack, which we couldn't infer the offset for.
                currentDisplacements[offs.second] = "L->stack";
                break;
            }
        }

        if (currentDisplacements.size() != correctDisplacements.size())
            // the fuck.
            return std::make_shared<VMShuffleResult>(false, std::map<std::string, std::vector<MapInfo> >{});


        for (const auto &[offsetName, offsetDiff]: currentDisplacements) {
            dumperState.OffsetMap[offsetDiff] = offsetName;
        }

        std::map<std::string, std::vector<MapInfo> > disassemblyMap{};

        std::map<std::string, std::string> mapKeyToValue = {
            {"L->top", "a1"},
            {"L->base", "a2"},
            {"L->global", "a3"},
            {"L->ci", "a4"},
            {"L->stack_last", "a5"},
            {"L->stack", "a6"},
        };

        disassemblyMap["VMShuffle6"] = {
            {"a1", mapKeyToValue[currentDisplacements[correctDisplacements["L->top"]]]},
            {"a2", mapKeyToValue[currentDisplacements[correctDisplacements["L->base"]]]},
            {"a3", mapKeyToValue[currentDisplacements[correctDisplacements["L->global"]]]},
            {"a4", mapKeyToValue[currentDisplacements[correctDisplacements["L->ci"]]]},
            {"a5", mapKeyToValue[currentDisplacements[correctDisplacements["L->stack_last"]]]},
            {"a6", mapKeyToValue[currentDisplacements[correctDisplacements["L->stack"]]]},
        };

        return std::make_shared<VMShuffleResult>(true, disassemblyMap);
    }
} // RobloxDumper
