//
// Created by Dottik on 20/10/2024.
//

#pragma once
#include <map>
#include <string>
#include <vector>

#include "../DumperState.hpp"
#include "AnalysisTasks/TaskBase.hpp"
#include "VMShuffle3And5.hpp"

namespace RobloxDumper::AnalysisTasks::VmShuffles {
    class VMShuffle7 final : public TaskBase<VMShuffleResult> {
    public:
        ~VMShuffle7() override = default;

        std::shared_ptr<VMShuffleResult> Analyse(RobloxDumper::DumperState &dumperState) override;
    };
} // RobloxDumper::AnalysisTasks::VmShuffles
