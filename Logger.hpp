//
// Created by Dottik on 10/8/2024.
//
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace RobloxDumper {
    enum LogType {
        Information, Warning, Error, Debug
    };

    class Logger final {
        /// @brief Private, Static shared pointer into the instance.
        static std::shared_ptr<Logger> pInstance;

        /// @brief Disables buffering.
        bool m_bInstantFlush;
        /// @brief Defines whether the Logger instance is initialized or not.
        bool m_bInitialized;
        /// @brief The size of the buffer.
        std::uint32_t m_dwBufferSize;
        /// @brief The buffer used to store messages.
        std::string m_szMessageBuffer;

        /// @brief Flushes the buffer into the standard output.
        void Flush(RobloxDumper::LogType messageType);

        /// @brief Flushes the buffer only if the buffer is full.
        void FlushIfFull(RobloxDumper::LogType messageType);

    public:
        /// @brief Obtains the Singleton for the Logger instance.
        /// @return Returns a shared pointer to the global Logger singleton instance.
        static std::shared_ptr<Logger> GetSingleton();

        void OpenStandard();

        /// @brief Initializes the Logger instance by opening the standard pipes, setting up the buffer and its size.
        /// @param bInstantFlush Whether the logger should keep no buffer, and let the underlying implementation for stdio
        /// and files handle it.
        void Initialize(bool bInstantFlush);

        void PrintDebug(std::string_view sectionName, std::string_view msg, std::string_view line);

        /// @brief Emits an Information with the given section name into the Logger's buffer.
        /// @param sectionName The name of the section that the code is running at
        /// @param msg The content to write into the buffer, as an information.
        /// @param line
        void PrintInformation(std::string_view sectionName, std::string_view msg, std::string_view line);

        /// @brief Emits a Warning with the given section name into the Logger's buffer.
        /// @param sectionName The name of the section that the code is running at
        /// @param msg The content to write into the buffer, as a warning.
        /// @param line
        void PrintWarning(std::string_view sectionName, std::string_view msg, std::string_view line);

        /// @brief Emits an error with the given section name into the Logger's buffer.
        /// @param sectionName The name of the section that the code is running at
        /// @param msg The content to write into the buffer, as an error.
        /// @param line
        void PrintError(std::string_view sectionName, std::string_view msg, std::string_view line);
    };


    /// @brief Defines a section for use in the logger
#define DefineSectionName(varName, sectionName) constexpr auto varName = sectionName
    DefineSectionName(MainThread, "RobloxDumper::MainThread");
    DefineSectionName(Anonymous, "RobloxDumper::Anonymous");
    DefineSectionName(SigMatcher, "RobloxDumper::SignatureMatcher");
    DefineSectionName(StrMatcher, "RobloxDumper::StringMatcher");

    DefineSectionName(Analysis_XrefSearcher, "RobloxDumper::Analysis::XrefSearcher");
    DefineSectionName(Analysis_RTTI, "RobloxDumper::Analysis::RTTI");
    DefineSectionName(Analysis_Disassembler, "RobloxDumper::Analysis::Disassembler");
#undef DefineSectionName
}; // namespace RbxStu

#define RobloxDumperLog(logType, sectionName, logMessage) {                     \
    const auto logger = RobloxDumper::Logger::GetSingleton();                         \
    switch (logType) {                                                          \
        case RobloxDumper::LogType::Information:                                      \
            logger->PrintInformation(sectionName, logMessage, __FUNCTION__);    \
            break;                                                              \
        case RobloxDumper::LogType::Warning:                                          \
            logger->PrintWarning(sectionName, logMessage, __FUNCTION__);        \
            break;                                                              \
        case RobloxDumper::LogType::Error:                                            \
            logger->PrintError(sectionName, logMessage, __FUNCTION__);          \
            break;                                                              \
        case RobloxDumper::LogType::Debug:                                            \
            logger->PrintDebug(sectionName, logMessage, __FUNCTION__);          \
            break;                                                              \
        }                                                                       \
    }
