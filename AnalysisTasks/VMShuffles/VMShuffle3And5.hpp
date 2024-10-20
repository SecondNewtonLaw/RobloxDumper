//
// Created by Dottik on 20/10/2024.
//

#pragma once
#include <format>
#include <map>
#include <string>
#include <vector>

#include "../DumperState.hpp"
#include "AnalysisTasks/TaskBase.hpp"

namespace RobloxDumper::AnalysisTasks::VmShuffles {
    struct MapInfo {
        std::string original;
        std::string mapped;
    };

    struct VMShuffleResult {
        bool bIsSuccessful;
        std::map<std::string, std::vector<MapInfo> > ShuffleMap;

        std::vector<std::string> ToCMacros() {
            std::vector<std::string> result;

            for (auto it = ShuffleMap.begin(); it != ShuffleMap.end(); ++it) {
                auto macroName = it->first;
                std::string macroText = std::format("#define {}(", macroName);

                for (const auto &mapInfo: it->second)
                    macroText = std::format("{}{}, ", macroText, mapInfo.original);

                macroText = std::format("{}sep) ", macroText);

                for (auto ji = it->second.begin(); ji != it->second.end(); ++ji) {
                    if (ji != it->second.end() - 1) {
                        macroText = std::format("{}{} sep ", macroText, ji->mapped);
                    } else {
                        macroText = std::format("{}{}", macroText, ji->mapped);
                    }
                }

                result.push_back(macroText);
            }

            return result;
        }
    };

    class VMShuffle3And5 final : public TaskBase<VMShuffleResult> {
    public:
        ~VMShuffle3And5() override = default;

        std::shared_ptr<VMShuffleResult> Analyse(RobloxDumper::DumperState &dumperState) override;
    };
} // RobloxDumper::AnalysisTasks::VmShuffles
