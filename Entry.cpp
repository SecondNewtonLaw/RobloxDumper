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

#include "Analysis/Disassembler.hpp"
#include "Analysis/StringSearcher.hpp"
#include "Analysis/XrefSearcher.hpp"
#include "AnalysisTasks/VMShuffles/VMShuffle3And5.hpp"
#include "AnalysisTasks/VMShuffles/VMShuffle7And8.hpp"

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
                    std::format("Loading {} into memory...", filename));
    LoadLibraryA(filename.c_str());
    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread, "Bootstrapping analysis tools...");

    auto stringSearcher = RobloxDumper::Analysis::StringSearcher::GetSingleton();
    auto xrefSearcher = RobloxDumper::Analysis::XrefSearcher::GetSingleton();
    auto signatureMatcher = RobloxDumper::SignatureMatcher::GetSingleton();
    auto hRobloxModule = hat::process::get_module("RobloxPlayerBeta.exe").value();

    xrefSearcher->BootstrapXrefsForModule(hRobloxModule);

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::MainThread,
                    "Analysis tools ready. Step 1/2 Signature Scanning");

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
                                            }
                                        });

    signatureMatcher->LoadSignaturePack("RBX::Luau", std::map<std::string, hat::signature>{
                                            {
                                                "lua_type",
                                                hat::parse_signature(
                                                    "83 FA FF 75 08 48 8D 05 ? ? ? ? C3 48 63 C2 48 8D 0D ? ? ? ? 48 8B 04 C1 C3")
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
                                        });

    auto rbxStuDisassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();

    RobloxDumper::DumperState state{};

    auto FoundSignatures = signatureMatcher->RunMatcher("RobloxPlayerBeta.exe", hRobloxModule);

    state.FunctionMap = FoundSignatures;

    auto VMShuffleDumps = std::vector<std::shared_ptr<RobloxDumper::AnalysisTasks::TaskBase<
        RobloxDumper::AnalysisTasks::VmShuffles::VMShuffleResult> > >{};

    if (FoundSignatures.contains("lua_type")) {
        VMShuffleDumps.emplace_back(std::make_shared<RobloxDumper::AnalysisTasks::VmShuffles::VMShuffle3And5>());
    }

    if (FoundSignatures.contains("luaG_aritherror")) {
        VMShuffleDumps.emplace_back(std::make_shared<RobloxDumper::AnalysisTasks::VmShuffles::VMShuffle7And8>());
    }

    std::println("- VMShuffles: ");
    for (const auto &vmShuffle: VMShuffleDumps) {
        for (auto shuffles = vmShuffle->Analyse(state); const auto &shuffle: shuffles->ToCMacros()) {
            std::println("{}", shuffle);
        }
    }

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
