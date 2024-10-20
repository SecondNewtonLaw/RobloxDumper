//
// Created by Dottik on 12/10/2024.
//

#include "Disassembler.hpp"
#include "Logger.hpp"

#include <mutex>
#include <optional>
#include <sstream>
#include <Windows.h>

#include <capstone/capstone.h>

RobloxDumper::Analysis::DisassembledChunk::~DisassembledChunk() {
    cs_free(this->originalInstruction, this->instructionCount);
}

RobloxDumper::Analysis::DisassembledChunk::DisassembledChunk(cs_insn *pInstructions, std::size_t ullInstructionCount) {
    std::size_t count = 0;
    this->vInstructionsvec.reserve(ullInstructionCount);
    for (std::size_t i = 0; i < ullInstructionCount; i++) {
        this->vInstructionsvec.push_back(*(pInstructions + i));
    }

    this->instructionCount = ullInstructionCount;
    this->originalInstruction = pInstructions;
    // Freeing correctly will result in freeing pInstructions->detail, which we do not want,
    // but we also do not want to free other things like the pInstructions, because else we CANNOT free detail later on.
    // cs_free is to run when deconstructing for simplicity.
    // cs_free(pInstructions, ullInstructionCount);
}

bool RobloxDumper::Analysis::DisassembledChunk::ContainsInstruction(const char *szMnemonic,
                                                                    const char *szOperationAsString,
                                                                    bool bUseContains) {
    for (const auto &instr: this->vInstructionsvec) {
        if (!bUseContains && (!szMnemonic || strcmp(instr.mnemonic, szMnemonic) == 0) &&
            (!szOperationAsString || strcmp(instr.op_str, szOperationAsString) == 0)) {
            return true;
        }

        if (bUseContains && (!szMnemonic || strstr(instr.mnemonic, szMnemonic) != nullptr) &&
            (!szOperationAsString || strstr(instr.op_str, szOperationAsString) != nullptr)) {
            return true;
        }
    }

    return false;
}

std::optional<const cs_insn> RobloxDumper::Analysis::DisassembledChunk::GetInstructionWhichMatches(
    const char *szMnemonic,
    const char *szOperationAsString,
    bool bUseContains) {
    for (const auto &instr: this->vInstructionsvec) {
        if (!bUseContains && (szMnemonic && strcmp(instr.mnemonic, szMnemonic) == 0 || !szMnemonic) &&
            (szOperationAsString && strcmp(instr.op_str, szOperationAsString) == 0 || !szOperationAsString)) {
            return instr;
        }

        if (bUseContains && (szMnemonic && strstr(instr.mnemonic, szMnemonic) != nullptr || !szMnemonic) &&
            (szOperationAsString && strstr(instr.op_str, szOperationAsString) != nullptr || !szOperationAsString)) {
            return instr;
        }
    }

    return {};
}

std::vector<cs_insn> RobloxDumper::Analysis::DisassembledChunk::GetInstructions() { return this->vInstructionsvec; }

std::string RobloxDumper::Analysis::DisassembledChunk::RenderInstructions() {
    std::stringstream strstream{};

    for (const auto &insn: this->GetInstructions()) {
        strstream << std::format("{}"
                                 ":\t{}\t\t{}\n",
                                 reinterpret_cast<void *>(insn.address), insn.mnemonic, insn.op_str);
    }

    return strstream.str();
}


std::shared_ptr<RobloxDumper::Analysis::Disassembler> RobloxDumper::Analysis::Disassembler::pInstance;

std::mutex RbxStuDisassemblerSingleton;

void RobloxDumper::Analysis::Disassembler::Initialize() {
    if (this->IsInitialized()) return; // Already initialized

    if (auto status = cs_open(cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_64, &this->m_capstoneHandle);
        status != cs_err::CS_ERR_OK) {
        throw std::exception("cannot initialize disassembler. Reason: capstone couldn't be initialized!");
    }

    cs_option(this->m_capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(this->m_capstoneHandle, CS_OPT_SKIPDATA, CS_OPT_ON);

    this->m_bIsInitialized = true;
}

bool RobloxDumper::Analysis::Disassembler::IsInitialized() {
    return this->m_bIsInitialized;
}

std::optional<std::unique_ptr<RobloxDumper::Analysis::DisassembledChunk> >
RobloxDumper::Analysis::Disassembler::GetInstructions(_In_ const void *startAddress, const void *endAddress,
                                                      const bool ignorePageProtection) const {
    const auto logger = Logger::GetSingleton();
    // Not true, it's mutated on Initialized, lol, stupid ReSharper.
    // ReSharper disable once CppDFAConstantConditions
    if (!this->m_bIsInitialized) {
        RobloxDumperLog(RobloxDumper::LogType::Warning, RobloxDumper::Analysis_Disassembler,
                        "Cannot comply with disassembly request: Disassembler not initialized!");
        return {};
    }

    // FFS ITS NOT UNREACHABLE DUDE.

    const auto segmentSize = std::abs(reinterpret_cast<std::intptr_t>(startAddress) -
                                      reinterpret_cast<std::intptr_t>(endAddress));

    if (!ignorePageProtection) {
#define CHECK_NOT_FLAG(num, flag) ((num & flag) != flag)
        MEMORY_BASIC_INFORMATION buf{nullptr};
        VirtualQuery(startAddress, &buf, sizeof(buf));
        // ReSharper disable once CppRedundantComplexityInComparison
        if (CHECK_NOT_FLAG(buf.Protect, PAGE_EXECUTE) && CHECK_NOT_FLAG(buf.Protect, PAGE_EXECUTE_READ) &&
            CHECK_NOT_FLAG(buf.Protect, PAGE_EXECUTE_READWRITE) && CHECK_NOT_FLAG(buf.Protect, PAGE_GRAPHICS_EXECUTE)) {
            //RbxStuLog(RbxStu::LogType::Debug, RbxStu::Analysis_Disassembler,
            //          "Memory protections are non-executable! Disassembly will not proceed.");
            return {};
        }
#undef CHECK_NOT_FLAG
    }

    // RobloxDumperLog(RbxStu::LogType::Debug, RbxStu::Analysis_Disassembler,
    //                 std::format("Disassembling segment: {} ~ {}. Size: {:#x}", startAddress,
    //                     endAddress, segmentSize));

    cs_insn *instructions{nullptr};

    auto disassembledCount = cs_disasm(
        this->m_capstoneHandle,
        static_cast<const uint8_t *>(const_cast<const void *>(startAddress)), segmentSize,
        reinterpret_cast<std::uintptr_t>(startAddress), segmentSize, &instructions);

    if (disassembledCount > 0) {
        //RbxStuLog(RbxStu::LogType::Debug, RbxStu::Analysis_Disassembler,
        //          "Serializing instructions into a DisassembledChunk instance!");
        return std::make_unique<DisassembledChunk>(instructions, disassembledCount);
    }

    RobloxDumperLog(RobloxDumper::LogType::Error, RobloxDumper::Analysis_Disassembler,
                    "Failed to disassemble the given address range!");

    return {};
}

const void *RobloxDumper::Analysis::Disassembler::GetFunctionStart(const void *address) {
    if (!this->IsInitialized()) return nullptr; // Not initialized.

    auto pointerCast = static_cast<const unsigned char *>(address);

    // Addresses become smaller the more we reach the BaseAddress of the Module.

    while (*--pointerCast != 0xCC || *--pointerCast != 0xCC)
        _mm_pause();


    return pointerCast + 2; // Go forward to go after the INT3.
}

const void *RobloxDumper::Analysis::Disassembler::GetFunctionEnd(const void *address) {
    if (!this->IsInitialized()) return nullptr; // Not initialized.
    auto pointerCast = static_cast<const unsigned char *>(address);

    // Addresses become bigger the further we are of the Module.

    while (*++pointerCast != 0xCC || *++pointerCast != 0xCC)
        _mm_pause();


    return pointerCast - 2; // Go backwards to go before the INT3.
}

std::optional<const void *>
RobloxDumper::Analysis::Disassembler::TranslateRelativeLeaIntoRuntimeAddress(const cs_insn &insn) {
    if (!this->IsInitialized()) return {}; // Not initialized.

    if (insn.id != x86_insn::X86_INS_LEA) return {};

    if (insn.detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) return {};

    if (insn.detail->x86.operands[1].mem.base != X86_REG_RIP) return {};

    const auto disposition = insn.detail->x86.operands[1].mem.disp;

    return reinterpret_cast<void *>(disposition + insn.address + insn.size);
}

std::shared_ptr<RobloxDumper::Analysis::Disassembler> RobloxDumper::Analysis::Disassembler::GetSingleton() {
    if (RobloxDumper::Analysis::Disassembler::pInstance == nullptr)
        RobloxDumper::Analysis::Disassembler::pInstance = std::make_shared<RobloxDumper::Analysis::Disassembler>();

    if (!RobloxDumper::Analysis::Disassembler::pInstance->IsInitialized()) {
        std::scoped_lock lock{RbxStuDisassemblerSingleton};
        if (RobloxDumper::Analysis::Disassembler::pInstance->IsInitialized())
            return RobloxDumper::Analysis::Disassembler::pInstance;

        RobloxDumper::Analysis::Disassembler::pInstance->Initialize();
    }

    return RobloxDumper::Analysis::Disassembler::pInstance;
}

csh *RobloxDumper::Analysis::Disassembler::GetCapstoneHandle() {
    return &this->m_capstoneHandle;
}
