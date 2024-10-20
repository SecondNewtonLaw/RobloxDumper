//
// Created by Dottik on 20/10/2024.
//

#include <format>

#include "SignatureMatcher.hpp"
#include "Logger.hpp"
#include "Utilities.hpp"


namespace RobloxDumper {
    std::shared_ptr<RobloxDumper::SignatureMatcher> SignatureMatcher::pInstance;

    std::shared_ptr<RobloxDumper::SignatureMatcher> SignatureMatcher::GetSingleton() {
        if (nullptr == RobloxDumper::SignatureMatcher::pInstance)
            RobloxDumper::SignatureMatcher::pInstance = std::make_shared<RobloxDumper::SignatureMatcher>();

        return RobloxDumper::SignatureMatcher::pInstance;
    }

    void SignatureMatcher::LoadSignaturePack(const std::string &packName,
                                             const std::map<std::string, hat::signature> &signaturePack) {
        if (!this->m_signaturePacks.contains(packName)) {
            RobloxDumperLog(RobloxDumper::LogType::Warning, RobloxDumper::SigMatcher,
                            std::format(
                                "The provided signature pack {} has already been loaded into memory, ignoring call.",
                                packName, signaturePack.size()
                            ));
            return;
        }

        RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::SigMatcher,
                        std::format("Loading signature pack {} with {} functions...", packName, signaturePack.size()));

        this->m_signaturePacks[packName] = signaturePack;
    }

    std::map<std::string, void *> SignatureMatcher::RunMatcher(const std::string_view moduleName,
                                                               const hat::process::module &hModule) {
        std::map<std::string, void *> results{};

        for (const auto &[packName, signaturePack]: this->m_signaturePacks) {
            RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::SigMatcher,
                            std::format("Matching signature pack {}...", packName));

            auto scanResults = Utilities::ScanMany(signaturePack, true);

            for (auto it = scanResults.begin(); it != scanResults.end(); ++it) {
                RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::SigMatcher,
                                std::format("- Found signature {} in {}+{}", it->first, moduleName, (hModule.address() -
                                    reinterpret_cast<std::uintptr_t>(it->second.get()))));
                results[it->first] = it->second.get();
            }
        }

        return results;
    }
} // RobloxDumper
