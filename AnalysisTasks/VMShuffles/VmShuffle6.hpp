//
// Created by Dottik on 21/10/2024.
//

#pragma once
#include "VMShuffle3And5.hpp"

namespace RobloxDumper::AnalysisTasks::VmShuffles {
    class VMShuffle6 final : public TaskBase<VMShuffleResult> {
    public:
        ~VMShuffle6() override = default;

        std::shared_ptr<VMShuffleResult> Analyse(RobloxDumper::DumperState &dumperState) override;
    };
} // RobloxDumper
