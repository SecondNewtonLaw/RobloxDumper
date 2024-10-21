//
// Created by Dottik on 20/10/2024.
//

#include <format>

#include "StringMatcher.hpp"

#include "Logger.hpp"
#include "Utilities.hpp"
#include "Analysis/StringSearcher.hpp"
#include "Analysis/XrefSearcher.hpp"

namespace RobloxDumper {
    std::shared_ptr<RobloxDumper::StringMatcher> RobloxDumper::StringMatcher::pInstance;

    std::shared_ptr<RobloxDumper::StringMatcher> StringMatcher::GetSingleton() {
        if (nullptr == RobloxDumper::StringMatcher::pInstance)
            RobloxDumper::StringMatcher::pInstance = std::make_shared<RobloxDumper::StringMatcher>();

        return RobloxDumper::StringMatcher::pInstance;
    }

    void StringMatcher::LoadStringPack(const std::string &packName,
                                       const std::map<std::string, std::string_view> &stringPack) {
        if (this->m_stringPacks.contains(packName)) {
            RobloxDumperLog(RobloxDumper::LogType::Warning, RobloxDumper::SigMatcher,
                            std::format(
                                "The provided string pack {} has already been loaded into memory, ignoring call.",
                                packName, stringPack.size()
                            ));
            return;
        }

        RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::SigMatcher,
                        std::format("Loading signature pack {} with {} functions...", packName, stringPack.size()));


        /*
         *  Scanning for strings is incredibly easy. We just need to make the string into AOBs, and scan the section we need :)
         */

        const auto stringSearcher = RobloxDumper::Analysis::StringSearcher::GetSingleton();

        auto sigifiedStrings = std::map<std::string, hat::signature>{};
        for (auto it = stringPack.begin(); it != stringPack.end(); ++it) {
            sigifiedStrings[it->first] = stringSearcher->ToAOB(it->second);
        }

        this->m_stringPacks[packName] = sigifiedStrings;
    }

    std::map<std::string, std::vector<void *> > StringMatcher::RunMatcher(std::string_view moduleName,
                                                                          const hat::process::module &hModule) {
        std::map<std::string, std::vector<void *> > results{};

        const auto disassembler = RobloxDumper::Analysis::Disassembler::GetSingleton();
        const auto xrefSearcher = Analysis::XrefSearcher::GetSingleton();
        for (const auto &[packName, signaturePack]: this->m_stringPacks) {
            RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::StrMatcher,
                            std::format("Matching string pack {}...", packName));

            auto scanResults = Utilities::ScanMany(hModule, signaturePack, true, ".rdata");

            for (auto it = scanResults.begin(); it != scanResults.end(); ++it) {
                if (!it->second.has_result()) {
                    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::StrMatcher,
                                    std::format("- Could not find remote string for {} in {}", it->first, moduleName));
                    continue;
                }
                RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::StrMatcher,
                                std::format("- Found string {} in {}+{}; Resolving XREFs", it->first, moduleName,
                                    reinterpret_cast<
                                    void *>(reinterpret_cast<std::uintptr_t>(it->second.get()) - hModule.
                                        address())));

                // Due to the fact the XREFs are STRAIGHT instructions, they're not the start of functions
                // we are after function declarations, not middle of functions, so we must find the function start.
                auto alignedMap = std::vector<void *>{};

                for (const auto &ref: xrefSearcher->GetXrefsForPointer(it->second.get()))
                    alignedMap.push_back(const_cast<void *>(disassembler->GetFunctionStart(ref)));

                for (const auto &xref: alignedMap) {
                    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::StrMatcher,
                                    std::format("\t- Found function with xref {}+{} (function start)", moduleName,
                                        reinterpret_cast<
                                        void *>(reinterpret_cast<std::uintptr_t>(xref) - hModule.
                                            address())));
                }

                results[it->first] = alignedMap;
            }
        }

        return results;
    }
} // RobloxDumper
