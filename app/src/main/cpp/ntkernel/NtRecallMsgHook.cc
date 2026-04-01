//
// Created by sulfate on 2023-05-17.
//

#include "NtRecallMsgHook.h"

#include <optional>
#include <cstdint>
#include <cinttypes>
#include <array>
#include <jni.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <span>
#include <optional>
#include <sys/mman.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <type_traits>
//#include <chrono>
#include <unordered_map>
#include <memory>
#include <unordered_set>
#include <fmt/format.h>

#include "qauxv_core/NativeCoreBridge.h"
#include "utils/Log.h"
#include "qauxv_core/HostInfo.h"
#include "utils/ProcessView.h"
#include "utils/ThreadUtils.h"
#include "utils/TextUtils.h"
#include "utils/AobScanUtils.h"
#include "utils/MemoryUtils.h"
#include "utils/arch_utils.h"
#include "utils/endian.h"
#include "utils/AntiDetectionHook.h"
#include <thread>
#include <chrono>
#include <functional>
#include <cerrno>
#include "qauxv_core/natives_utils.h"
#include "qauxv_core/linker_utils.h"
#include "qauxv_core/jni_method_registry.h"

#ifndef STACK_GUARD
// for debug purpose only
#define STACK_GUARD ((void) 0)
#endif

namespace ntqq::hook {

using namespace qauxv;
using namespace ::utils;

static volatile bool sIsHooked = false;

EXPORT extern "C" void* gLibkernelBaseAddress = nullptr;

// Anti-detection configuration (conservative defaults)
// Set USE_ANTI_DETECTION_HOOK to true only if Dobby hook is being detected
static bool gEnableAntiDetection = false;  // Disable anti-detection hook by default (Dobby works fine)
static bool gDelayedHook = false;          // Disable delayed hook (may cause timing issues)
static bool gHideMemoryPermissions = true; // Enable memory permission hiding (recommended)

// Backup storage for original instructions (for temporary restoration during detections)
static std::unordered_map<void*, std::vector<uint8_t>> gOriginalInstructions;

// Back up a region of the target function's original instructions
static void BackupOriginalInstructions(void* targetAddr, size_t len = 32) {
    if (targetAddr == nullptr) return;
    auto it = gOriginalInstructions.find(targetAddr);
    if (it != gOriginalInstructions.end()) return; // already backed up
    std::vector<uint8_t> buf(len);
    memcpy(buf.data(), targetAddr, len);
    gOriginalInstructions[targetAddr] = std::move(buf);
}

// Restore previously backed up instructions
static void RestoreOriginalInstructions(void* targetAddr) {
    auto it = gOriginalInstructions.find(targetAddr);
    if (it == gOriginalInstructions.end()) return;
    const auto& buf = it->second;
    memcpy(targetAddr, buf.data(), buf.size());
    gOriginalInstructions.erase(it);
}

// Restore memory permissions to RX after hook
static void HideMemoryPermissionsForRange(void* addr, size_t len) {
    if (addr == nullptr || len == 0) return;
    size_t ps = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t start = reinterpret_cast<uintptr_t>(addr);
    uintptr_t alignedStart = start & ~(ps - 1);
    uintptr_t end = start + len;
    uintptr_t alignedEnd = (end + ps - 1) & ~(ps - 1);
    size_t totalLen = static_cast<size_t>(alignedEnd - alignedStart);
    int rc = mprotect(reinterpret_cast<void*>(alignedStart), totalLen, PROT_READ | PROT_EXEC);
    if (rc != 0) {
        LOGE("HideMemoryPermissions mprotect failed errno={}", errno);
    }
}

static void HideMemoryPermissions(void* addr, size_t len) {
    HideMemoryPermissionsForRange(addr, len);
}

// Delayed hook helper
static void DelayedHook(std::function<void()> task) {
    std::thread([task]() {
        // Simple delay to wait QQ's anti-tamper checks finish
        std::this_thread::sleep_for(std::chrono::seconds(2));
        task();
    }).detach();
}

// Intercept detection-related functions (best-effort)
static bool InterceptDetectionFunctions(void* moduleBase, size_t moduleSize) {
    if (!gEnableAntiDetection) return true;
    if (moduleBase == nullptr || moduleSize == 0) return true;
    // Try to initialize anti-detection hooks in the target module
    int rc = qauxv::antidetect::InitAntiDetectHook(moduleBase, moduleSize);
    if (rc == 0) {
        void* padding = qauxv::antidetect::FindTextPadding(moduleBase, moduleSize, 32);
        if (padding) {
            LOGD("Anti-detection: padding found at {:p}", padding);
        }
    } else {
        LOGW("Anti-detection: InitAntiDetectHook failed: {}", rc);
    }
    return true;
}

jclass klassRevokeMsgHook = nullptr;
jobject gInstanceRevokeMsgHook = nullptr;
jmethodID handleRecallSysMsgFromNtKernel = nullptr;

// Forward declarations
bool PerformNtRecallMsgHookWithAntiDetect(uint64_t baseAddress);
bool PerformNtRecallMsgHookWithDobby(uint64_t baseAddress);

void (* sOriginHandleGroupRecallSysMsgCallback)(void*, void*, void*) = nullptr;

void HandleGroupRecallSysMsgCallback([[maybe_unused]] void* x0, void* x1, [[maybe_unused]] void* x2, [[maybe_unused]] int x3) {
    // LOGD("HandleGroupRecallSysMsgCallback start p1={:p}, p2={:p}, p3={:p}", x0, x1, x2);
}

void (* sOriginHandleC2cRecallSysMsgCallback)(void*, void*, void*) = nullptr;

void HandleC2cRecallSysMsgCallback([[maybe_unused]] void* p1, [[maybe_unused]] void* p2, void* p3, [[maybe_unused]] int x3) {
    if (p3 == nullptr || *(void**) p3 == nullptr) {
        LOGE("HandleC2cGroupSysMsgCallback BUG !!! *p3 = null, this should not happen!!!");
        return;
    }
    // LOGD("HandleC2cRecallSysMsgCallback start p1={:p}, p2={:p}, p3={:p}", p1, p2, p3);
}

bool PerformNtRecallMsgHook(uint64_t baseAddress) {
    if (sIsHooked) {
        return true;
    }
    sIsHooked = true;
    gLibkernelBaseAddress = reinterpret_cast<void*>(baseAddress);

    if (gEnableAntiDetection) {
        if (antidetect::InitAntiDetectHook(gLibkernelBaseAddress, 0x1000000) == 0) {
            LOGD("PerformNtRecallMsgHook: using anti-detection trampoline hook");
            return PerformNtRecallMsgHookWithAntiDetect(baseAddress);
        }
        LOGW("PerformNtRecallMsgHook: anti-detection init failed, falling back to Dobby");
    }

    return PerformNtRecallMsgHookWithDobby(baseAddress);
}

bool PerformNtRecallMsgHookWithAntiDetect(uint64_t baseAddress) {
    const uint64_t currentVersion = qauxv::HostInfo::GetLongVersionCode();
    const uint64_t Version_QQ_9_2_20 = 11650;

    auto targetRecallC2cSysMsg = AobScanTarget()
            .WithName("RecallC2cSysMsg")
            .WithSequence({0x09, 0x8d, 0x40, 0xf8, 0x00, 0x03, 0x00, 0xaa, 0x21, 0x00, 0x80, 0x52, 0xf3, 0x03, 0x02, 0xaa, 0x29, 0x00, 0x40, 0xf9})
            .WithMask({0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff})
            .WithStep(4)
            .WithExecMemOnly(true)
            .WithOffsetsForResult({-0x20, -0x24, -0x28, -0x3c})
            .WithResultValidator(CommonAobScanValidator::kArm64StpX29X30SpImm);

    AobScanTarget targetRecallGroupSysMsg;
    if (currentVersion >= Version_QQ_9_2_20) {
        targetRecallGroupSysMsg = AobScanTarget()
                .WithName("RecallGroupSysMsg")
                .WithSequence({0x09, 0x8d, 0x40, 0xf8, 0x29, 0x95, 0x40, 0xf9, 0x00, 0x00, 0x00, 0x94, 0x00, 0x04, 0x00, 0x36, 0x00, 0x02, 0x40, 0xf9, 0x61,
                               0x00, 0x80, 0x52})
                .WithMask({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff})
                .WithStep(4)
                .WithExecMemOnly(true)
                .WithOffsetsForResult({-0x44})
                .WithResultValidator(CommonAobScanValidator::kArm64StpX29X30SpImm);
    } else {
        targetRecallGroupSysMsg = AobScanTarget()
                .WithName("RecallGroupSysMsg")
                .WithSequence({0x28, 0x00, 0x40, 0xf9, 0x61, 0x00, 0x80, 0x52, 0x09, 0x8d, 0x40, 0xf8, 0x29, 0x00, 0x40, 0xf9})
                .WithMask({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff})
                .WithStep(4)
                .WithExecMemOnly(true)
                .WithOffsetsForResult({-0x18, -0x24, -0x28})
                .WithResultValidator(CommonAobScanValidator::kArm64StpX29X30SpImm);
    }

    std::vector<std::string> errorMsgList;
    if (!SearchForAllAobScanTargets({&targetRecallC2cSysMsg, &targetRecallGroupSysMsg}, gLibkernelBaseAddress, true, errorMsgList)) {
        LOGE("PerformNtRecallMsgHookWithAntiDetect SearchForAllAobScanTargets failed");
        for (const auto& msg: errorMsgList) {
            TraceError(nullptr, gInstanceRevokeMsgHook, msg);
        }
        return false;
    }

    uint64_t offsetC2c = targetRecallC2cSysMsg.GetResultOffset();
    uint64_t offsetGroup = targetRecallGroupSysMsg.GetResultOffset();

    if (offsetC2c != 0) {
        void* c2c = (void*) (baseAddress + offsetC2c);
        BackupOriginalInstructions(c2c, 32);
        antidetect::AntiDetectHookContext ctxC2c = {};
        ctxC2c.targetAddr = c2c;
        ctxC2c.hookAddr = (void*) &HandleC2cRecallSysMsgCallback;
        ctxC2c.moduleBase = gLibkernelBaseAddress;
        ctxC2c.moduleSize = 0x1000000;

        int rc = antidetect::TextPaddingTrampolineHook(&ctxC2c);
        if (rc != 0) {
            LOGE("PerformNtRecallMsgHookWithAntiDetect: TextPaddingTrampolineHook c2c failed, falling back to Dobby");
            RestoreOriginalInstructions(c2c);
            return PerformNtRecallMsgHookWithDobby(baseAddress);
        }
        sOriginHandleC2cRecallSysMsgCallback = (void (*)(void*, void*, void*)) ctxC2c.trampolineAddr;
        LOGD("PerformNtRecallMsgHookWithAntiDetect: c2c hook installed, trampoline={:p}", ctxC2c.trampolineAddr);
        if (gHideMemoryPermissions) {
            HideMemoryPermissions(c2c, 32);
        }
    } else {
        TraceErrorF(nullptr, gInstanceRevokeMsgHook, "PerformNtRecallMsgHookWithAntiDetect failed, offsetC2c == 0");
    }

    if (offsetGroup != 0) {
        void* group = (void*) (baseAddress + offsetGroup);
        BackupOriginalInstructions(group, 32);
        antidetect::AntiDetectHookContext ctxGroup = {};
        ctxGroup.targetAddr = group;
        ctxGroup.hookAddr = (void*) &HandleGroupRecallSysMsgCallback;
        ctxGroup.moduleBase = gLibkernelBaseAddress;
        ctxGroup.moduleSize = 0x1000000;

        int rc = antidetect::TextPaddingTrampolineHook(&ctxGroup);
        if (rc != 0) {
            LOGE("PerformNtRecallMsgHookWithAntiDetect: TextPaddingTrampolineHook group failed, falling back to Dobby");
            RestoreOriginalInstructions(group);
            if (offsetC2c == 0) {
                return PerformNtRecallMsgHookWithDobby(baseAddress);
            }
        }
        sOriginHandleGroupRecallSysMsgCallback = (void (*)(void*, void*, void*)) ctxGroup.trampolineAddr;
        LOGD("PerformNtRecallMsgHookWithAntiDetect: group hook installed, trampoline={:p}", ctxGroup.trampolineAddr);
        if (gHideMemoryPermissions) {
            HideMemoryPermissions(group, 32);
        }
    } else {
        TraceErrorF(nullptr, gInstanceRevokeMsgHook, "PerformNtRecallMsgHookWithAntiDetect failed, offsetGroup == 0");
    }
    return true;
}

bool PerformNtRecallMsgHookWithDobby(uint64_t baseAddress) {
    const uint64_t currentVersion = qauxv::HostInfo::GetLongVersionCode();
    const uint64_t Version_QQ_9_2_20 = 11650;

    //@formatter:off

    auto targetRecallC2cSysMsg = AobScanTarget()
            .WithName("RecallC2cSysMsg")
            .WithSequence({0x09, 0x8d, 0x40, 0xf8, 0x00, 0x03, 0x00, 0xaa, 0x21, 0x00, 0x80, 0x52, 0xf3, 0x03, 0x02, 0xaa, 0x29, 0x00, 0x40, 0xf9})
            .WithMask(    {0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff})
            .WithStep(4)
            .WithExecMemOnly(true)
            .WithOffsetsForResult({-0x20, -0x24, -0x28, -0x3c})
            .WithResultValidator(CommonAobScanValidator::kArm64StpX29X30SpImm);

    AobScanTarget targetRecallGroupSysMsg;
     if (currentVersion >= Version_QQ_9_2_20) {
        targetRecallGroupSysMsg = AobScanTarget()
                .WithName("RecallGroupSysMsg")
                .WithSequence({0x09, 0x8d, 0x40, 0xf8, 0x29, 0x95, 0x40, 0xf9, 0x00, 0x00, 0x00, 0x94, 0x00, 0x04, 0x00, 0x36, 0x00, 0x02, 0x40, 0xf9, 0x61, 0x00, 0x80, 0x52})
                .WithMask(    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
                .WithStep(4)
                .WithExecMemOnly(true)
                .WithOffsetsForResult({-0x44})
                .WithResultValidator(CommonAobScanValidator::kArm64StpX29X30SpImm);
    } else {
         targetRecallGroupSysMsg = AobScanTarget()
                 .WithName("RecallGroupSysMsg")
                 .WithSequence({0x28, 0x00, 0x40, 0xf9, 0x61, 0x00, 0x80, 0x52, 0x09, 0x8d, 0x40, 0xf8, 0x29, 0x00, 0x40, 0xf9})
                 .WithMask(    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff})
                 .WithStep(4)
                 .WithExecMemOnly(true)
                 .WithOffsetsForResult({-0x18, -0x24, -0x28})
                 .WithResultValidator(CommonAobScanValidator::kArm64StpX29X30SpImm);
    }

    //@formatter:on

    std::vector<std::string> errorMsgList;
    if (!SearchForAllAobScanTargets({&targetRecallC2cSysMsg, &targetRecallGroupSysMsg}, gLibkernelBaseAddress, true, errorMsgList)) {
        LOGE("PerformNtRecallMsgHookWithDobby SearchForAllAobScanTargets failed");
        for (const auto& msg: errorMsgList) {
            TraceError(nullptr, gInstanceRevokeMsgHook, msg);
        }
        return false;
    }

    uint64_t offsetC2c = targetRecallC2cSysMsg.GetResultOffset();
    uint64_t offsetGroup = targetRecallGroupSysMsg.GetResultOffset();

    if (offsetC2c != 0) {
        void* c2c = (void*) (baseAddress + offsetC2c);
        if (CreateInlineHook(c2c, (void*) &HandleC2cRecallSysMsgCallback, (void**) &sOriginHandleC2cRecallSysMsgCallback) != 0) {
            TraceErrorF(nullptr, gInstanceRevokeMsgHook,
                        "PerformNtRecallMsgHookWithDobby failed, DobbyHook c2c failed, c2c={:p}({:x}+{:x})",
                        c2c, baseAddress, offsetC2c);
            return false;
        }
    } else {
        TraceErrorF(nullptr, gInstanceRevokeMsgHook, "PerformNtRecallMsgHookWithDobby failed, offsetC2c == 0");
    }
    if (offsetGroup != 0) {
        void* group = (void*) (baseAddress + offsetGroup);
        if (CreateInlineHook(group, (void*) &HandleGroupRecallSysMsgCallback, (void**) &sOriginHandleGroupRecallSysMsgCallback) != 0) {
            TraceErrorF(nullptr, gInstanceRevokeMsgHook,
                        "PerformNtRecallMsgHookWithDobby failed, DobbyHook group failed, group={:p}({:x}+{:x})",
                        group, baseAddress, offsetGroup);
            return false;
        }
    } else {
        TraceErrorF(nullptr, gInstanceRevokeMsgHook, "PerformNtRecallMsgHookWithDobby failed, offsetGroup == 0");
    }
    return true;
}


bool InitInitNtKernelRecallMsgHook() {
    using namespace ::utils;
    if (sIsHooked) {
        LOGW("InitInitNtKernelRecallMsgHook failed, already hooked");
        return false;
    }
    const auto fnHookProc = &PerformNtRecallMsgHook;
    ProcessView self;
    if (int err;(err = self.readProcess(getpid())) != 0) {
        TraceErrorF(nullptr, gInstanceRevokeMsgHook, "InitInitNtKernelRecallMsgHook failed, readProcess failed: {}", err);
        return false;
    }
    std::optional<ProcessView::Module> libkernel;
    for (const auto& m: self.getModules()) {
        if (m.name == "libkernel.so") {
            libkernel = m;
            break;
        }
    }
    if (libkernel.has_value()) {
        // LOGD("libkernel.so is already loaded");
        // hook now or delay based on config
        if (gDelayedHook) {
            DelayedHook([fnHookProc, base = libkernel->baseAddress]() {
                // Intercept potential detections before actual hook
                InterceptDetectionFunctions(reinterpret_cast<void*>(base), 0);
                fnHookProc(base);
            });
            return true;
        } else {
            // Intercept potential detections before actual hook
            InterceptDetectionFunctions(reinterpret_cast<void*>(libkernel->baseAddress), 0);
            return fnHookProc(libkernel->baseAddress);
        }
    } else {
        int rc = RegisterLoadLibraryCallback([fnHookProc](const char* name, void* handle) {
            if (name == nullptr) {
                return;
            }
            std::string soname;
            // LOGD("dl_dlopen: {}", name);
            // get suffix
            auto suffix = strrchr(name, '/');
            if (suffix == nullptr) {
                soname = name;
            } else {
                soname = suffix + 1;
            }
            if (soname == "libkernel.so") {
                // LOGD("dl_dlopen: libkernel.so is loaded, start hook");
                // get base address
                ProcessView self2;
                if (int err;(err = self2.readProcess(getpid())) != 0) {
                    TraceErrorF(nullptr, gInstanceRevokeMsgHook, "InitInitNtKernelRecallMsgHook failed, readProcess failed: {}", err);
                    return;
                }
                std::optional<ProcessView::Module> libkernel2;
                for (const auto& m: self2.getModules()) {
                    if (m.name == "libkernel.so") {
                        libkernel2 = m;
                        break;
                    }
                }
                if (libkernel2.has_value()) {
                    // hook now
                    if (!fnHookProc(libkernel2->baseAddress)) {
                        TraceErrorF(nullptr, gInstanceRevokeMsgHook, "InitInitNtKernelRecallMsgHook failed, fnHookProc failed");
                    }
                } else {
                    TraceErrorF(nullptr, gInstanceRevokeMsgHook, "InitInitNtKernelRecallMsgHook failed, but it was loaded");
                }
            }
        });
        if (rc < 0) {
            // it's better to report this error somehow
            TraceErrorF(nullptr, gInstanceRevokeMsgHook, "InitInitNtKernelRecallMsgHook failed, RegisterLoadLibraryCallback failed: {}", rc);
            return false;
        }
        // LOGD("libkernel.so is not loaded, register callback");
        return true;
    }
}

} // ntqq::hook

extern "C" JNIEXPORT jboolean JNICALL
Java_cc_ioctl_hook_msg_RevokeMsgHook_nativeInitNtKernelRecallMsgHookV1p2(JNIEnv* env, jobject thiz) {
    using ntqq::hook::klassRevokeMsgHook;
    using ntqq::hook::gInstanceRevokeMsgHook;
    using ntqq::hook::handleRecallSysMsgFromNtKernel;
    if (klassRevokeMsgHook == nullptr) {
        jclass clazz = env->GetObjectClass(thiz);
        if (clazz == nullptr) {
            LOGE("InitInitNtKernelRecallMsgHook failed, GetObjectClass failed");
            return false;
        }
        klassRevokeMsgHook = (jclass) env->NewGlobalRef(clazz);
        gInstanceRevokeMsgHook = env->NewGlobalRef(thiz);
        handleRecallSysMsgFromNtKernel = env->GetStaticMethodID(clazz, "handleRecallSysMsgFromNtKernel",
                                                                "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JJJJI)V");
        if (handleRecallSysMsgFromNtKernel == nullptr) {
            LOGE("InitInitNtKernelRecallMsgHook failed, GetStaticMethodID failed");
            return false;
        }
    }
    auto ret = ntqq::hook::InitInitNtKernelRecallMsgHook();
    if (!ret) {
        LOGE("InitInitNtKernelRecallMsgHook failed");
    }
    return ret;
}

//@formatter:off
static JNINativeMethod gMethods[] = {
        {"nativeInitNtKernelRecallMsgHookV1p2", "()Z", reinterpret_cast<void*>(Java_cc_ioctl_hook_msg_RevokeMsgHook_nativeInitNtKernelRecallMsgHookV1p2)},

};
//@formatter:on
REGISTER_SECONDARY_FULL_INIT_NATIVE_METHODS("cc/ioctl/hook/msg/RevokeMsgHook", gMethods);
