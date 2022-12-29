#include "pch.h"

#define WIN32_LEAN_AND_MEAN

struct COUNTERS
{
    int rules_matching;
    int rules_not_matching;
    int rules_warning;
    PVOID BaseAddress;
    PVOID VirtualBaseAddress;
};

int count(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    YR_RULE* rule = (YR_RULE*)message_data;
    YR_STRING* string;

    switch (message)
    {
    case CALLBACK_MSG_TOO_MANY_MATCHES:
        (*(struct COUNTERS*)user_data).rules_warning++;
        break;

    case CALLBACK_MSG_RULE_MATCHING:
        (*(struct COUNTERS*)user_data).rules_matching++;
        yr_rule_strings_foreach(rule, string) {
            std::cout << "[*] Rule Match: " << rule->identifier << " on block address: " << (PVOID)((uintptr_t)(*(struct COUNTERS*)user_data).BaseAddress) << std::endl;
        }
        break;

    case CALLBACK_MSG_RULE_NOT_MATCHING:
        (*(struct COUNTERS*)user_data).rules_not_matching++;
    }
    return CALLBACK_CONTINUE;
}

void Scanner(void* data) {
    const char RuleStr[] =
        "rule RuleName : ruler"
        "{"
        "meta:"
        "description = \"Example Rule\""
        "			threat_level = 5"
        "		strings:"
        "			$c = \"SAMPLE_STRING\" wide ascii"
        "		condition:"
        "			$c"
        "	}"
        "";

    if (yr_initialize() != ERROR_SUCCESS)
        return;
    
    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;
    
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        return;
    
    if (yr_compiler_add_string(compiler, RuleStr, nullptr) != ERROR_SUCCESS)
        return;
    
    if (yr_compiler_get_rules(compiler, &rules) == ERROR_SUCCESS)
        std::cout << "[+] New Yara Rule Loaded in DLL" << std::endl;
    else
        return;

    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    BOOL FIRST = TRUE;
    PVOID BA = nullptr;

    std::wstring SKIP_MEMORYDLL     =   L"memoryscanner.dll";
    PVOID SKIP_MEMORYDLL_ADDR = nullptr;
    PVOID SKIP_MEMORYDLL_ADDR_FINAL = nullptr;

    MODULEINFO moduleInfo;
    size_t i;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                if (FIRST) {
                    BA = hMods[i];
                    FIRST = FALSE;
                }

                if (wcsstr(szModName, SKIP_MEMORYDLL.c_str())) {
                    if (!GetModuleInformation(hProcess, hMods[i], &moduleInfo, sizeof(moduleInfo))) {
                        printf("GetModuleInformation Error\n");
                        return;
                    }
                    SKIP_MEMORYDLL_ADDR = hMods[i];
                    SKIP_MEMORYDLL_ADDR_FINAL = static_cast<BYTE*>(moduleInfo.lpBaseOfDll) + moduleInfo.SizeOfImage;
                }
            }
        }
    }
    
    std::cout << "Binary Base Address: \t\t0x" << BA << std::endl;
    std::cout << "Memory DLL Base Address: \t0x" << SKIP_MEMORYDLL_ADDR << std::endl;
    std::cout << "Memory DLL Final Address: \t0x" << SKIP_MEMORYDLL_ADDR_FINAL << std::endl;

    HMODULE hModule = NULL;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, L"!", &hModule))
        return;
    
    unsigned char* addr = (unsigned char*)BA;
    MEMORY_BASIC_INFORMATION mbi;

#ifdef SHOW_MEMORY_BLOCK
    char* buffer{ nullptr };
    SIZE_T bytesRead;
#endif

    struct COUNTERS ud;

    ud.rules_not_matching = 0;
    ud.rules_matching = 0;
    ud.rules_warning = 0;
    ud.VirtualBaseAddress = BA;
    
    char MaliciusBlock[] = "SAMPLE_STRING";
    std::cout << "Allocating Memory for malicious [string]" << std::endl;
    
    uintptr_t Target = (uintptr_t)BA + (uintptr_t)0x2000;
    DWORD oldP = 0;
    auto retVP = VirtualProtectEx(hProcess, (LPVOID)Target, 32, PAGE_READWRITE, &oldP);
    if (!retVP) {
        std::cout << "VirtualProtectEx Error\n";
        return;
    }

    SIZE_T bmt = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID)Target, &MaliciusBlock, (DWORD)sizeof(MaliciusBlock), nullptr)) {
        printf("WriteProcessMemory Error\n");
        return;
    }

    std::cout << "Malicius was allocate at\t0x" << (PVOID)Target << std::endl;

    std::cout << "Scanning Process Memory" << std::endl;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.BaseAddress >= (PVOID)Target && mbi.BaseAddress <= (PVOID)Target)
            std::cout << "Scanning .data section:\t0x" << mbi.BaseAddress << std::endl;


        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD && mbi.Protect != (PAGE_GUARD | PAGE_READWRITE)) {
            if ( !(mbi.BaseAddress >= SKIP_MEMORYDLL_ADDR && mbi.BaseAddress <= SKIP_MEMORYDLL_ADDR_FINAL) ) {
                ud.BaseAddress = mbi.BaseAddress;
                if (yr_rules_scan_mem(rules, (const uint8_t*)mbi.BaseAddress, mbi.RegionSize, 0, count, &ud, 5) != ERROR_SUCCESS)
                    break;
                
#ifdef SHOW_MEMORY_BLOCK
                delete[] buffer;
                buffer = new char[mbi.RegionSize];

                if (ud.rules_matching > 0) {
                    std::cout << mbi.AllocationProtect << std::endl;
                    std::cout << mbi.State << std::endl;
                    std::cout << mbi.Protect << std::endl;
                    std::cout << mbi.Type << std::endl;
                    std::cout << (0x40000 | 0x20000) << std::endl;

                    if (!ReadProcessMemory(hProcess, (void*)mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                        std::cout << "deu ruim";
                        break;
                    }

                    std::cout << "read:" << bytesRead << buffer << std::endl;
                    for (size_t i = 0; i < mbi.RegionSize; i++) {
                        printf("%c", (unsigned char)buffer[i]);
                    }
                }
                ud.rules_not_matching = 0;
                ud.rules_matching = 0;
                ud.rules_warning = 0;
#endif
                ud.BaseAddress = nullptr;
            }
            else {
                std::cout << "Bypass Allow List DLL in region block: 0x" << (PVOID)((unsigned long long) mbi.BaseAddress + (unsigned long long)BA)<< std::endl;
            }
        }
        addr += mbi.RegionSize;
    }
    CloseHandle(hProcess);
}

void SpawnAgent() {
    HANDLE hL = (HANDLE)_beginthread(&Scanner, 0, 0);
    CloseHandle(hL);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        SpawnAgent();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
