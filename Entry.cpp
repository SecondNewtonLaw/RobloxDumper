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
        if (!foundSignatures.contains("lua_type")) {
            std::println("Cannot dump VMShuffle 3 and 5; Missing lua_type!");
            break;
        }
        std::println("Attempting to dump VMShuffle 3 and 5");

        auto possibleInstructions = rbxStuDisassembler->GetInstructions(foundSignatures["lua_type"],
                                                                        reinterpret_cast<void *>(
                                                                            reinterpret_cast<std::uintptr_t>(
                                                                                foundSignatures
                                                                                ["lua_type"]) + 0x1D),
                                                                        true);

        if (!possibleInstructions.has_value()) {
            std::println("Cannot dump VMShuffle 3 and 5!");
            break;
        }
        auto instructions = std::move(possibleInstructions.value());

        auto loadTableAddress = instructions->GetInstructionWhichMatches("lea", "rcx, [rip +", true);

        if (!loadTableAddress.has_value()) {
            std::println("Cannot dump VMShuffle 3 and 5! Failed to match.");
            break;
        }
        const auto loadTableInstruction = loadTableAddress.value();
        const auto possibleTypeTable = rbxStuDisassembler->TranslateRelativeLeaIntoRuntimeAddress(
            loadTableInstruction);

        if (!possibleTypeTable.has_value()) {
            std::println("Cannot dump VMShuffle 3 and 5! Failed to obtain type table.");
            break;
        }

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
        auto tableOrder = std::vector<const char *>{
            typeTable[0], // nil
            typeTable[1], // boolean

            typeTable[2], // shuffled (should be userdata) a2 a1
            typeTable[3], // shuffled (should be number) a3 a2
            typeTable[4], // shuffled (should be vector) a1 a3

            typeTable[5], // string

            typeTable[6], // shuffled (should be table)
            typeTable[7], // shuffled (should be function)
            typeTable[8], // shuffled (should be userdata)
            typeTable[9], // shuffled (should be thread)
            typeTable[10] // shuffled (should be buffer)
        };

        auto vmShuffle3 = std::map<std::string_view, std::string>{
            {"userdata", "a1"}, {"number", "a2"}, {"vector", "a3"}
        };

        auto vmShuffle5 = std::map<std::string_view, std::string>{
            {"table", "a1"}, {"function", "a2"}, {"userdata", "a3"}, {"thread", "a4"}, {"buffer", "a5"}
        };

        std::println(R"(
#define VMShuffle3(sep, a1, a2, a3) {} sep {} sep {} sep
#define VMShuffle5(sep, a1, a2, a3, a4, a5) {} sep {} sep {} sep {} sep {} sep
)",
                     // VMValue3
                     vmShuffle3[tableOrder[2]], vmShuffle3[tableOrder[3]], vmShuffle3[tableOrder[4]],

                     // VMValue5
                     vmShuffle5[tableOrder[6]], vmShuffle5[tableOrder[7]], vmShuffle5[tableOrder[8]],
                     vmShuffle5[tableOrder[9]], vmShuffle5[tableOrder[10]]
        );

        std::println("VMShuffle 3 and 5 cracked successfully!");
        break;
    }

    while (true) {
        if (!foundSignatures.contains("luaG_aritherror")) {
            std::println("Cannot dump VMShuffle 7; Missing luaG_aritherror!");
            break;
        }
        std::println("Attempting to dump VMShuffle 7...");

        auto possibleInstructions = rbxStuDisassembler->GetInstructions(foundSignatures["luaG_aritherror"],
                                                                        reinterpret_cast<void *>(
                                                                            reinterpret_cast<std::uintptr_t>(
                                                                                foundSignatures
                                                                                ["luaG_aritherror"]) + 0x4C),
                                                                        true);

        if (!possibleInstructions.has_value()) {
            std::println("Cannot dump VMShuffle 7; cannot disassemble");
            break;
        }

        const auto disassembledChunk = std::move(possibleInstructions.value());

        const auto targetInsn = disassembledChunk->GetInstructionWhichMatches("lea", "r8, [rip +", true);

        if (!targetInsn.has_value()) {
            std::println("Cannot dump VMShuffle 7; missing target LEA instruction into r8 from relative offset.");
            break;
        }

        const auto leaEventNmesTable = targetInsn.value();

        const auto eventNames = rbxStuDisassembler->TranslateRelativeLeaIntoRuntimeAddress(leaEventNmesTable);

        if (!eventNames.has_value()) {
            std::println("Cannot dump VMShuffle 7; failed to resolve relative lea.");
            break;
        }

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

        std::println(R"(
#define VMShuffle7(sep, a1, a2, a3, a4, a5, a6, a7) {} sep {} sep {} sep {} sep {} sep {} sep {} sep
)",
                     vmShuffle7["__index"],
                     vmShuffle7["__newindex"],
                     vmShuffle7["__mode"],
                     vmShuffle7["__namecall"],
                     vmShuffle7["__call"],
                     vmShuffle7["__iter"],
                     vmShuffle7["__len"]
        );

        std::println("VMShuffle 7 cracked successfully!");
        break;
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
