//
// Created by Dottik on 11/10/2024.
//

#include <Windows.h>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <filesystem>
#include <print>
#include <fstream>
#include <iostream>

#include <libhat/Signature.hpp>
#include <libhat/Scanner.hpp>

#include "Logger.hpp"
#include "SignatureMatcher.hpp"
#include "StringMatcher.hpp"

#include "Analysis/Disassembler.hpp"
#include "Analysis/StringSearcher.hpp"
#include "Analysis/XrefSearcher.hpp"
#include "AnalysisTasks/VMShuffles/VMShuffle3And5.hpp"
#include "AnalysisTasks/VMShuffles/VmShuffle6.hpp"
#include "AnalysisTasks/VMShuffles/VMShuffle7And8.hpp"
#include "AnalysisTasks/VMValues/GlobalState.hpp"

static __inline std::map<std::string_view, hat::signature> AOBSignatures{
    {
        "RBX::ScriptContext::task_defer",
        hat::parse_signature(
            "40 55 53 56 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 4C 8B F1 48 C7 45 ? ? ? ? ? 4C 8D 4D ? 4C 8D 05 ? ? ? ? 33 D2 E8 ? ? ? ? 44 8B E0 4D 85 F6 74 06 49 8B 46 ?")
        .value()
    },
    {
        "RBX::TaskSchedulerMK2::GetSingleton (Inlined, Fragment)",
        hat::parse_signature("E8 ? ? ? ? 48 85 C0 74 36 48 89 44 24 ? 48 8B C8 E8 ? ? ? ? 90 48 89 05 ? ? ? ?").value()
    },
    {
        "lua_type",
        hat::parse_signature("83 FA FF 75 08 48 8D 05 ? ? ? ? C3 48 63 C2 48 8D 0D ? ? ? ? 48 8B 04 C1 C3").value()
    },
    {
        "luaD_rawrununprotected",
        hat::parse_signature(
            "48 89 4C 24 ? 48 83 EC ? 48 8B C2 49 8B D0 FF 15 C3 F6 67 01 33 C0 EB 04 8B 44 24 48 48 83 C4 ? C3").
        value()
    },
    {
        "luaG_aritherror",
        hat::parse_signature(
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 63 F9 49 8B D8 48 8B E9 E8 ? ? ? ? 48 8B D3 48 8B CD 48 8D 70 ? E8 ? ? ? ? 4C 8D 05 ? ? ? ? 48 83 C0 ? 4D 8B 04 F8 4C 8B CE 49 83 C0 ?")
        .value()
    },
    {
        "RBX::StandardOut::print",
        hat::parse_signature(
            "48 89 5C 24 ? 57 48 83 EC ? 41 8B D8 8B F9 33 C0 48 89 44 24 ? 48 89 44 24 ? 48 C7 44 24 ? ? ? ? ? 88 44 24 ? 49 C7 C0 ? ? ? ? 90 49 FF C0 42 38 04 02 75 F7")
        .value()
    },
    {
        "RBX::fireTouchRemotely",
        hat::parse_signature(
            "48 8B 0E 45 33 C9 44 0F B6 C7 48 8B D3 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 ? 5F E9 ? ? ? ?").value()
    }
};

int main(const int argc, const char **argv, const char **envp) {
    if (argc != 2) {
        std::println("usage: {} <decrypted roblox path>", argv[0]);
        return 0;
    }
    RobloxDumper::Logger::GetSingleton()->Initialize(true);

    const auto filename = std::string(argv[1]);

    if (!std::filesystem::exists(filename)) {
        RobloxDumperLog(RobloxDumper::LogType::Error, RobloxDumper::MainThread,
                        std::format("cannot load {} into memory! The file does not exist or is not viewable by {}.",
                            filename, argv[0]));
        Sleep(5000);
        return EXIT_FAILURE;
    }

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    std::format(
                        "Loading {} into memory utilising LoadLibraryExA(..., nullptr, DONT_RESOLVE_DLL_REFERENCES)...",
                        filename));
    LoadLibraryExA(filename.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread, "Bootstrapping analysis tools...");

    auto stringMatcher = RobloxDumper::StringMatcher::GetSingleton();
    auto stringSearcher = RobloxDumper::Analysis::StringSearcher::GetSingleton();
    auto xrefSearcher = RobloxDumper::Analysis::XrefSearcher::GetSingleton();
    auto signatureMatcher = RobloxDumper::SignatureMatcher::GetSingleton();
    auto hRobloxModule = hat::process::get_module("RobloxPlayerBeta.exe").value();

    xrefSearcher->BootstrapXrefsForModule(hRobloxModule);

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Analysis tools ready. Step 1/2 Signature & String Scanning");

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    std::format("Target In-Memory Address: {}", reinterpret_cast<void *>(hRobloxModule.address())));

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [1/2] -- Loading Signature Packs...");

    signatureMatcher->LoadSignaturePack("RBX::Basics", std::map<std::string, hat::signature>{
                                            {
                                                "RBX::StandardOut::print",
                                                hat::parse_signature(
                                                    "48 89 5C 24 ? 57 48 83 EC ? 41 8B D8 8B F9 33 C0 48 89 44 24 ? 48 89 44 24 ? 48 C7 44 24 ? ? ? ? ? 88 44 24 ? 49 C7 C0 ? ? ? ? 90 49 FF C0 42 38 04 02 75 F7")
                                                .value()
                                            },
                                            {
                                                "RBX::fireTouchRemotely",
                                                hat::parse_signature(
                                                    "48 8B 0E 45 33 C9 44 0F B6 C7 48 8B D3 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 ? 5F E9 ? ? ? ?")
                                                .value()
                                            },
                                            {
                                                "RBX::Instance::pushInstance",
                                                hat::parse_signature(
                                                    "48 89 5C 24 ? 57 48 83 EC 20 48 8B FA 48 8B D9 E8 ? ? ? ? 84 C0 74 ? 48 8B D7 48 8B CB 48 8B 5C 24")
                                                .value()
                                            },
                                            {
                                                "RBX::Instance::getTopAncestor",
                                                hat::parse_signature(
                                                    "48 8B 41 ? 48 85 C0 74 08 48 8B C8 E9 EF FF FF FF 48 8B C1 C3").
                                                value()
                                            },
                                            {
                                                "RBX::ScriptContext::checkRequirePermission",
                                                hat::parse_signature(
                                                    "48 89 5C 24 ? 48 89 6C 24 ? 48 89 54 24 ? 56 57 41 56 48 83 EC ? 4C 8B F2 4C 8B C9 48 8B 32 48 8B CE E8 ? ? ? ? 48 8B F8 4C 8B D8 49 81 E3 ? ? ? ?")
                                                .value()
                                            }
                                        });

    signatureMatcher->LoadSignaturePack("RBX::Luau::Partials", std::map<std::string, hat::signature>{
                                            {
                                                "luaO_nilObject [ref]",
                                                hat::parse_signature(
                                                    "48 63 50 ? 8B CA 83 E1 ? 80 F9 05 75 06 4C 39 48 10 74 1F F7 C2 F0 FF FF FF 74 10 48 8B CA 48 C1 F9 ? 48 C1 E1 ? 48 03 C1")
                                                .value()
                                            },
                                            {
                                                "luaC_checkgc",
                                                hat::parse_signature(
                                                    "48 8B 41 ? 48 39 41 ? ? ? 41 0F B6 D4 48 8B CE E8 ? ? ? ?").
                                                value()
                                            }
                                        });

    signatureMatcher->LoadSignaturePack("RBX::Luau", std::map<std::string, hat::signature>{
                                            {
                                                "lua_type",
                                                hat::parse_signature(
                                                    "0F 84 4E FF FF FF 48 8D 35 ? ? ? ? 48 8B 34 CE")
                                                .value()
                                            },
                                            {
                                                "luaD_rawrununprotected",
                                                hat::parse_signature(
                                                    "48 89 4C 24 ? 48 83 EC ? 48 8B C2 49 8B D0 FF 15 C3 F6 67 01 33 C0 EB 04 8B 44 24 48 48 83 C4 ? C3")
                                                .
                                                value()
                                            },
                                            {
                                                "luaG_aritherror",
                                                hat::parse_signature(
                                                    "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 63 F9 49 8B D8 48 8B E9 E8 ? ? ? ? 48 8B D3 48 8B CD 48 8D 70 ? E8 ? ? ? ? 4C 8D 05 ? ? ? ? 48 83 C0 ? 4D 8B 04 F8 4C 8B CE 49 83 C0 ?")
                                                .value()
                                            },
                                        });

    signatureMatcher->LoadSignaturePack("RBX::Partials", std::map<std::string, hat::signature>{
                                            {
                                                "RBX::TaskSchedulerMK2::GetSingleton (Inlined, Fragment)",
                                                hat::parse_signature(
                                                    "E8 ? ? ? ? 48 85 C0 74 36 48 89 44 24 ? 48 8B C8 E8 ? ? ? ? 90 48 89 05 ? ? ? ?")
                                                .value()
                                            },
                                            {
                                                "RBX::ScriptContext::resumeWaitingThreads (Fragment)",
                                                hat::parse_signature(
                                                    "0F 84 EE 00 00 ? 48 8B 48 ? 48 85 C9 0F 84 E1 00 00 ? 48 8B 41 ? 48 39 41 ? 75 14 48 8B 41 ? 48 39 41 ? 75 0A 80 79 ? 00 0F 84 C3 00 00 ? BA ? ? ? ? E8 ? ? ? ?")
                                                .value()
                                            }
                                        });


    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [1/2] -- Loading String Packs...");

    stringMatcher->LoadStringPack("RBX::Luau::StringPartials", {
                                      {
                                          "task.desynchronize",
                                          "task.desynchronize() may only be called from a script that is a descendant of an Actor"
                                      },
                                      {
                                          "luaV_gettable",
                                          "\'__index\' chain too long; possible loop"
                                      },
                                      {
                                          "luaV_settable",
                                          "\'__newindex\' chain too long; possible loop"
                                      },
                                      {
                                          "dumptable",
                                          R"({"type":"table","cat":%d,"size":%d)"
                                      }
                                  });

    stringMatcher->LoadStringPack("RBX::StringPartials", {
                                      {
                                          "RBX::ScriptContext::runScript",
                                          "[FLog::ScriptContext] Running script %p"
                                      },
                                      {
                                          "RBX::World::reportTouchInfo",
                                          "new overlap in different world"
                                          // Contains some RBX::World and RBX::Primitive offsets.
                                      },
                                      {
                                          "RBX::ScriptContext::task_defer",
                                          "Maximum re-entrancy depth (%i) exceeded calling task.defer"
                                      },
                                      {
                                          "RBX::ScriptContext::resume",
                                          "[FLog::ScriptContext] Resuming script: %p"
                                      },
                                      {
                                          "RBX::ScriptContext::require",
                                          "Cannot require a RobloxScript module from a non RobloxScript context"
                                      },
                                      {
                                          "RBX::Security::threadAccessError",
                                          "Gur pheerag guernq pnaabg %f '%f' (ynpxvat pncnovyvgl %f)"
                                          // Caesar Cyphered in ROBLOX Client, different on ROBLOX Studio.
                                      },
                                      {
                                          "RBX::ScriptContextFacets::WaitingHybridScriptsJob::step",
                                          "[FLog::DataModelJobs] Waiting scripts start, data model: %p",
                                      },
                                      {
                                          "RBX::ScriptContextFacets::GCJob::step",
                                          "[FLog::DataModelJobs] GC Job start, data model: %p"
                                      },
                                      {
                                          "RBX::HeartbeatTask::step",
                                          "[FLog::DataModelJobs] Heartbeat start, data model: %p"
                                      },
                                      {
                                          "Color3.fromHex",
                                          "Color3.fromHex requires one argument"
                                      }
                                  });

    auto rbxStuDisassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();

    RobloxDumper::DumperState state{};

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [1/2] -- Running SignatureMatcher...");
    auto FoundSignatures = signatureMatcher->RunMatcher("RobloxPlayerBeta.exe", hRobloxModule);
    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [1/2] -- Running StringMatcher...");
    auto FoundFunctions = stringMatcher->RunMatcher("RobloxPlayerBeta.exe", hRobloxModule);

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [1/2] -- Saved result to current RobloxDumper::DumperState.");
    state.XrefMap = FoundFunctions;
    state.FunctionMap = FoundSignatures;

    while (true) {
        RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                        "Step [2/2] Obtaining additional functions through complex scanning...");

        if (state.FunctionMap.contains("luaC_checkgc")) {
            auto luaC_checkGcExpanded = state.FunctionMap.at("luaC_checkgc");

            auto insns = rbxStuDisassembler->GetInstructions(luaC_checkGcExpanded,
                                                             reinterpret_cast<void *>(
                                                                 reinterpret_cast<std::uintptr_t>(luaC_checkGcExpanded)
                                                                 + 0x1A),
                                                             true);

            if (!insns.has_value()) {
                break;
            }

            auto instructions = std::move(insns.value());

            auto callIntoCStep = instructions->GetInstructionWhichMatches("call", nullptr, true);

            if (!callIntoCStep.has_value())
                break;


            state.FunctionMap["luaC_step"] = reinterpret_cast<void *>(
                callIntoCStep.value().detail->x86.operands[
                    0].
                imm);

            RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                            std::format(
                                "Step [2/2] Determined address of luaC_step via function analysis. luaC_step: RobloxPlayerBeta.exe+{}"
                                ,reinterpret_cast<void*>(callIntoCStep.value().detail->x86.operands[0].imm -
                                    hRobloxModule.
                                    address())));
        } else {
            RobloxDumperLog(RobloxDumper::LogType::Warning, RobloxDumper::MainThread,
                            "Step [2/2] Cannot resolve luaC_step, missing luaC_checkgc");
        }


        break;
    }

    while (true) {
        RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                        "Step [2/2] FastFlag Analysis...");
        const auto data = hRobloxModule.get_section_data(".text");
        auto patterns = hat::find_all_pattern(data.begin(), data.end(),
                                              static_cast<hat::signature_view>(hat::compile_signature<
                                                  "48 83 EC ? 48 8B 0D ? ? ? ? 4C 8D 05 ? ? ? ? 41 B9 ? ? ? ? 48 8D 15 ? ? ? ?">()));


        for (const auto &scanned: patterns) {
            const auto result = scanned.get();
            auto possibleInsns = rbxStuDisassembler->GetInstructions(
                result, reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(result) + 0x29), true);

            if (!possibleInsns.has_value())
                continue;


            const auto insns = std::move(possibleInsns.value());

            const auto possibleLoadDataReference = insns->GetInstructionWhichMatches("lea", "r8, [rip + ", true);
            const auto possibleLoadFlagName = insns->GetInstructionWhichMatches("lea", "rdx, [rip + ", true);
            if (!possibleLoadDataReference.has_value() || !possibleLoadFlagName.has_value()) {
                RobloxDumperLog(RobloxDumper::LogType::Warning, RobloxDumper::MainThread,
                                "Cannot find the required assembly without them being "
                                "coupled! Function analysis may not continue."
                );
                continue;
            }
            const auto loadNameInsn = possibleLoadFlagName.value();
            const auto loadDataInsn = possibleLoadDataReference.value();

            const auto flagNameReference = rbxStuDisassembler->TranslateRelativeLeaIntoRuntimeAddress(loadNameInsn);
            const auto dataReference = rbxStuDisassembler->TranslateRelativeLeaIntoRuntimeAddress(loadDataInsn);

            if (!dataReference.has_value() || !flagNameReference.has_value()) {
                RobloxDumperLog(RobloxDumper::LogType::Warning, RobloxDumper::MainThread,
                                "Failed to translate the RIP-based offset into a memory address for any of the "
                                "LEA operations! This will result on bad things, thus, we cannot continue trying "
                                "to get this flag :("
                );
                continue;
            }

            state.FastFlagMap[static_cast<const char *>(flagNameReference.value())] = const_cast<void *>(dataReference.
                value());
        }

        if (state.FastFlagMap.contains("TaskSchedulerTargetFps")) {
            auto targetFps = state.FastFlagMap.at("TaskSchedulerTargetFps");
            RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                            std::format( "- Found TaskSchedulerTargetFps @ RobloxPlayerBeta.exe+{}", reinterpret_cast<
                                void *>(reinterpret_cast<std::uintptr_t>(targetFps) - hRobloxModule.
                                    address())));
        }

        break;
    }


    while (true) {
        if (state.FunctionMap.contains("RBX::TaskSchedulerMK2::GetSingleton (Inlined, Fragment)")) {
            auto target = state.FunctionMap.at("RBX::TaskSchedulerMK2::GetSingleton (Inlined, Fragment)");
            std::println("Attempting to resolve for RBX::TaskScheduler::pInstance");
            std::optional<std::unique_ptr<RobloxDumper::Analysis::DisassembledChunk> > disassembly = rbxStuDisassembler
                    ->
                    GetInstructions(static_cast<void *>(target),
                                    rbxStuDisassembler->GetFunctionEnd(
                                        static_cast<void *>(target)),
                                    true);

            if (!disassembly.has_value()) {
                std::println("Cannot resolve for RBX::TaskScheduler::pInstance!");
                continue;
            }
            const auto chunk = std::move(disassembly.value());
            const auto movePointer = chunk->GetInstructionWhichMatches("mov", "qword ptr [rip + ", true);
            if (!movePointer.has_value()) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }

            const auto insn = movePointer.value();

            if (insn.detail->x86.operands[0].type != x86_op_type::X86_OP_MEM) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }
            if (insn.detail->x86.operands[1].type != x86_op_type::X86_OP_REG) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }

            if (insn.detail->x86.operands[0].mem.base != X86_REG_RIP) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }

            const auto disposition = insn.detail->x86.operands[0].mem.disp;

            const auto offset = (disposition + insn.address + insn.size);


            std::println("Found RBX::TaskScheduler::pInstance @ RobloxPlayerBeta.exe+{}",
                         reinterpret_cast<void *>(offset - hRobloxModule.
                                                  address()));
        }

        break;
    }

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [2/2] Analysis...");

    auto VMValueDumps = std::vector<std::shared_ptr<RobloxDumper::AnalysisTasks::TaskBase<
        RobloxDumper::AnalysisTasks::VmValues::VMValueResult> > >{};
    while (true) {
        if (state.FunctionMap.contains("luaC_step")) {
            VMValueDumps.emplace_back(std::make_shared<RobloxDumper::AnalysisTasks::VmValues::GlobalState>());
        }

        break;
    }

    auto VMShuffleDumps = std::vector<std::shared_ptr<RobloxDumper::AnalysisTasks::TaskBase<
        RobloxDumper::AnalysisTasks::VmShuffles::VMShuffleResult> > >{};
    while (true) {
        if (state.FunctionMap.contains("lua_type")) {
            VMShuffleDumps.emplace_back(std::make_shared<RobloxDumper::AnalysisTasks::VmShuffles::VMShuffle3And5>());
        }

        if (state.FunctionMap.contains("RBX::ScriptContext::checkRequirePermission") && state.FunctionMap.
            contains("luaC_step") && state.XrefMap.contains("Color3.fromHex") && state.FunctionMap.contains(
                "RBX::ScriptContext::resumeWaitingThreads (Fragment)")) {
            VMShuffleDumps.emplace_back(std::make_shared<RobloxDumper::AnalysisTasks::VmShuffles::VMShuffle6>());
        }

        if (state.FunctionMap.contains("luaG_aritherror")) {
            VMShuffleDumps.emplace_back(std::make_shared<RobloxDumper::AnalysisTasks::VmShuffles::VMShuffle7And8>());
        }

        break;
    }

    while (true) {
        if (!FoundSignatures.contains("luaO_nilObject [ref]")) {
            break;
        }
        auto partialRef = FoundSignatures.at("luaO_nilObject [ref]");

        auto possibleInsns = rbxStuDisassembler->GetInstructions(
            partialRef, reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(partialRef) + 0x4C), true);

        if (!possibleInsns.has_value())
            break;

        auto disassembledChunk = std::move(possibleInsns.value());
        auto insn = disassembledChunk->GetInstructionWhichMatches("lea", "rax, [rip +", true);

        if (!insn.has_value())
            break;

        FoundSignatures["luaO_nilObject"] = const_cast<void *>(rbxStuDisassembler->
            TranslateRelativeLeaIntoRuntimeAddress(insn.value()).
            value());

        RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                        std::format("Step [2/2] luaO_nilObject @ RobloxPlayerBeta.exe+{}", reinterpret_cast<
                            void *>(reinterpret_cast<std::uintptr_t>(FoundSignatures["luaO_nilObject"]) - hRobloxModule.
                                address())));

        break;
    }


    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [2/2] Processing VMShuffles...");

    for (const auto &vmShuffle: VMShuffleDumps) {
        for (auto shuffles = vmShuffle->Analyse(state); const auto &shuffle: shuffles->ToCMacros()) {
            std::println("{}", shuffle);
        }
    }

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [2/2] Processed VMShuffles.");


    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [2/2] Processing VMValues...");

    for (const auto &vmValue: VMValueDumps) {
        auto analysisResult = vmValue->Analyse(state);
        RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                        std::format("- Found {} VMValue type: {}", analysisResult->vmValueIdentifier,
                            analysisResult->EncryptionTypeToString()));
    }

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Step [2/2] Processing VMValues.");

    return 0;

    auto foundSignatures = std::map<std::string_view, void *>();

    for (const auto &[offsetName, offsetSignature]: AOBSignatures) {
        hat::scan_result result = hat::find_pattern(
            offsetSignature,
            ".text",
            hRobloxModule);

        if (!result.has_result()) {
            std::println("Failed to find {} in RobloxPlayerBeta.exe! Update signature!", offsetName);
            continue;
        }

        foundSignatures[offsetName] = result.get();

        std::println("Found {} @ RobloxPlayerBeta.exe+{}", offsetName,
                     reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(result.get()) - hRobloxModule.
                                              address()));

        if (offsetName == "RBX::TaskSchedulerMK2::GetSingleton (Inlined, Fragment)") {
            std::println("Attempting to resolve for RBX::TaskScheduler::pInstance");
            std::optional<std::unique_ptr<RobloxDumper::Analysis::DisassembledChunk> > disassembly = rbxStuDisassembler
                    ->
                    GetInstructions(static_cast<void *>(result.get()),
                                    rbxStuDisassembler->GetFunctionEnd(
                                        static_cast<void *>(result.get())),
                                    true);

            if (!disassembly.has_value()) {
                std::println("Cannot resolve for RBX::TaskScheduler::pInstance!");
                continue;
            }
            const auto chunk = std::move(disassembly.value());
            const auto movePointer = chunk->GetInstructionWhichMatches("mov", "qword ptr [rip + ", true);
            if (!movePointer.has_value()) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }

            const auto insn = movePointer.value();

            if (insn.detail->x86.operands[0].type != x86_op_type::X86_OP_MEM) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }
            if (insn.detail->x86.operands[1].type != x86_op_type::X86_OP_REG) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }

            if (insn.detail->x86.operands[0].mem.base != X86_REG_RIP) {
                std::println(
                    "Cannot resolve RBX::TaskScheduler::pInstance! Cannot find required instruction to calculate offset.");
                continue;
            }

            const auto disposition = insn.detail->x86.operands[0].mem.disp;

            const auto offset = (disposition + insn.address + insn.size);


            std::println("Found RBX::TaskScheduler::pInstance @ RobloxPlayerBeta.exe+{}",
                         reinterpret_cast<void *>(offset - hRobloxModule.
                                                  address()));
        }
    }

    while (true) {
        std::println("Finding RBX::ScriptContext::resume...");
        auto stringPointer = stringSearcher->GetStringAddressInTarget(hRobloxModule,
                                                                      "[FLog::ScriptContext] Resuming script: %p");

        if (!stringPointer.has_value()) {
            std::println("Cannot find RBX::ScriptContext::resume, string not found in memory.");
            break;
        }

        auto xrefs = xrefSearcher->GetXrefsForPointer(stringPointer.value());

        for (const auto xref: xrefs) {
            auto functionStart = rbxStuDisassembler->GetFunctionStart(xref);
            foundSignatures["RBX::ScriptContext::resume"] = const_cast<void *>(functionStart);
        }

        std::println("Found RBX::ScriptContext::resume: RobloxPlayerBeta.exe+{}", reinterpret_cast<void *>(
                         reinterpret_cast<std::uintptr_t>(foundSignatures["RBX::ScriptContext::resume"]) -
                         hRobloxModule.
                         address()));

        break;
    }
}
