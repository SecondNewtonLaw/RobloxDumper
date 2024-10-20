//
// Created by Dottik on 20/10/2024.
//

#pragma once
#include <memory>

namespace RobloxDumper::AnalysisTasks {
    template<typename T>
    class TaskBase abstract {
    public:
        TaskBase() = default;

        virtual ~TaskBase() = default;

        virtual std::shared_ptr<T> Analyse(RobloxDumper::DumperState &dumperState) {
            return std::make_shared<T>();
        }
    };
}
