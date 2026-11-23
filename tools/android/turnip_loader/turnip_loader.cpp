#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <adrenotools/driver.h>

#define LOG_TAG "TurnipLoader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static void* g_turnip_handle = nullptr;

using dlopen_fn = void* (*)(const char*, int);
static dlopen_fn orig_dlopen = nullptr;

static void* hooked_dlopen(const char* filename, int flags) {
    if (filename != nullptr && g_turnip_handle != nullptr) {
        if (strcmp(filename, "libvulkan.so") == 0 ||
            strcmp(filename, "/system/lib64/libvulkan.so") == 0 ||
            strstr(filename, "libvulkan_freedreno.so") != nullptr) {
            LOGI("Redirecting dlopen('%s') -> Turnip R27 handle (%p)", filename, g_turnip_handle);
            return g_turnip_handle;
        }
    }
    return orig_dlopen ? orig_dlopen(filename, flags) : dlopen(filename, flags);
}

static int patch_plt_callback(struct dl_phdr_info* info, size_t size, void* data) {
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
    if (!strstr(info->dlpi_name, "librexruntime.so") &&
        !strstr(info->dlpi_name, "librexgpu-xenos.so") &&
        !strstr(info->dlpi_name, "libmain.so")) {
        return 0;
    }

    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    const ElfW(Rela)* jmprel = nullptr;
    size_t pltrelsz = 0;

    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:   symtab = reinterpret_cast<const ElfW(Sym)*>(dyn->d_un.d_ptr); break;
            case DT_STRTAB:   strtab = reinterpret_cast<const char*>(dyn->d_un.d_ptr); break;
            case DT_JMPREL:   jmprel = reinterpret_cast<const ElfW(Rela)*>(dyn->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = dyn->d_un.d_val; break;
        }
    }
    if (!symtab || !strtab || !jmprel || !pltrelsz) return 0;

    size_t count = pltrelsz / sizeof(ElfW(Rela));
    long page_size = sysconf(_SC_PAGESIZE);

    for (size_t i = 0; i < count; i++) {
        uint32_t sym_idx = ELF64_R_SYM(jmprel[i].r_info);
        const char* sym_name = strtab + symtab[sym_idx].st_name;
        if (strcmp(sym_name, "dlopen") == 0) {
            void** got_entry = reinterpret_cast<void**>(info->dlpi_addr + jmprel[i].r_offset);
            uintptr_t page_start = reinterpret_cast<uintptr_t>(got_entry) & ~(page_size - 1);
            if (mprotect(reinterpret_cast<void*>(page_start), page_size, PROT_READ | PROT_WRITE) == 0) {
                if (!orig_dlopen) orig_dlopen = reinterpret_cast<dlopen_fn>(*got_entry);
                *got_entry = reinterpret_cast<void*>(&hooked_dlopen);
                __builtin___clear_cache(reinterpret_cast<char*>(got_entry), reinterpret_cast<char*>(got_entry + 1));
                LOGI("Patched dlopen GOT in %s", info->dlpi_name);
            }
        }
    }
    return 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_gtavrecomp_app_GameActivity_nativeInitTurnip(JNIEnv* env, jclass clazz, jstring jNativeLibDir, jstring jTempDir) {
    const char* nativeLibDir = env->GetStringUTFChars(jNativeLibDir, nullptr);
    const char* tempDir = env->GetStringUTFChars(jTempDir, nullptr);

    std::string libDirStr(nativeLibDir);
    if (!libDirStr.empty() && libDirStr.back() != '/') libDirStr += '/';

    std::string tmpDirStr(tempDir);
    if (!tmpDirStr.empty() && tmpDirStr.back() != '/') tmpDirStr += '/';

    LOGI("Loading Turnip R27 from: %s", libDirStr.c_str());

    g_turnip_handle = adrenotools_open_libvulkan(
        RTLD_NOW | RTLD_LOCAL,
        ADRENOTOOLS_DRIVER_CUSTOM,
        tmpDirStr.c_str(),
        libDirStr.c_str(),
        libDirStr.c_str(),
        "libvulkan_freedreno.so",
        nullptr,
        nullptr
    );

    env->ReleaseStringUTFChars(jNativeLibDir, nativeLibDir);
    env->ReleaseStringUTFChars(jTempDir, tempDir);

    if (!g_turnip_handle) {
        LOGE("Failed to load Turnip R27 via libadrenotools!");
        return JNI_FALSE;
    }

    LOGI("Turnip R27 loaded successfully! Handle: %p", g_turnip_handle);
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_gtavrecomp_app_GameActivity_nativeHookVulkan(JNIEnv* env, jclass clazz) {
    if (!g_turnip_handle) return;
    dl_iterate_phdr(patch_plt_callback, nullptr);
}

