//
// Created by Dottik on 2/11/2024.
//

#pragma once

#include "VMShuffle3And5.hpp"

namespace RobloxDumper::AnalysisTasks::VmShuffles {
    class VMShuffle4 final : public TaskBase<VMShuffleResult> {
    public:
        std::shared_ptr<VMShuffleResult> Analyse(RobloxDumper::DumperState &dumperState) override;
    };
} // RobloxDumper::AnalysisTasks::VmShuffles
