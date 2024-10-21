//
// Created by Dottik on 21/10/2024.
//

#pragma once
#include "DumperState.hpp"
#include "AnalysisTasks/TaskBase.hpp"


namespace RobloxDumper::AnalysisTasks::VmValues {
    enum class PointerEncryptionType {
        XOR = 0,
        ADD,
        SUB_0,
        SUB_1,

        UNKNOWN
    };

    struct VMValueResult {
        std::string vmValueIdentifier;
        PointerEncryptionType encryptionType;

        bool WasSuccessful() {
            return this->encryptionType != RobloxDumper::AnalysisTasks::VmValues::PointerEncryptionType::UNKNOWN;
        }

        std::string EncryptionTypeToString() {
            switch (encryptionType) {
                case PointerEncryptionType::XOR:
                    return "EXCLUSIVE OR (STORAGE ^ SELF)";
                case PointerEncryptionType::ADD:
                    return "ADDITION (STORAGE + SELF)";
                case PointerEncryptionType::SUB_0:
                    return "SUBSTRACTION (STORAGE - SELF)";
                case PointerEncryptionType::SUB_1:
                    return "SUBSTRACTION (SELF - STORAGE)";
                case PointerEncryptionType::UNKNOWN:
                    return "COULD NOT DETERMINE AUTOMATICALLY :(";
            }

            return "???";
        }
    };

    class GlobalState final : public TaskBase<VMValueResult> {
    public:
        ~GlobalState() override = default;

        std::shared_ptr<VMValueResult> Analyse(RobloxDumper::DumperState &dumperState) override;
    };
} // RobloxDumper::AnalysisTasks::VmValues
