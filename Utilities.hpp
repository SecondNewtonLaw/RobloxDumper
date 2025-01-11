//
// Created by Dottik on 12/10/2024.
//

#pragma once
#include <filesystem>
#include <Logger.hpp>
#include <memory>
#include <regex>
#include <future>
#include <map>
#include <vector>
#include <libhat/Scanner.hpp>

#include <sstream>

#include <Windows.h>


namespace RobloxDumper {
    class Utilities {
        static std::shared_ptr<Utilities> pInstance;
        std::atomic_bool m_bIsInitialized;
        std::regex m_luaErrorStringRegex;

        void Initialize();

    public:
        bool IsInitialized();

        static std::shared_ptr<Utilities> GetSingleton();

        std::string FromLuaErrorMessageToCErrorMessage(const std::string &luauMessage) const;

        static std::string WcharToString(const wchar_t *wideStr);

        static std::string ToLower(std::string target);

        static std::string ToUpper(std::string target);

        __forceinline static bool IsWine() {
            return GetProcAddress(GetModuleHandle("ntdll.dll"), "wine_get_version") != nullptr;
        }


        __forceinline static std::vector<std::string> SplitBy(const std::string &target, const char split) {
            std::vector<std::string> splitted;
            std::stringstream stream(target);
            std::string temporal;
            while (std::getline(stream, temporal, split)) {
                splitted.push_back(temporal);
                temporal.clear();
            }

            return splitted;
        }

        template<typename T>
        static std::map<T, hat::scan_result> ScanMany(
            hat::process::module hModule,
            std::map<T, hat::signature> signatures,
            const bool parallelScan, const char *targetSection) {
            std::vector<std::future<std::pair<T, hat::scan_result> > > futures{};

            for (const auto sig: signatures) {
                futures.emplace_back(std::async(parallelScan ? std::launch::async : std::launch::deferred,
                                                [sig, hModule, targetSection]() {
                                                    return std::make_pair(
                                                        sig.first, hat::find_pattern(sig.second, targetSection, hModule));
                                                }));
            }

            std::map<T, hat::scan_result> results = {};
            for (auto &future: futures) {
                future.wait();
                auto result = future.get();
                results.emplace(result);
            }

            return results;
        }
    };
} // RbxStu
