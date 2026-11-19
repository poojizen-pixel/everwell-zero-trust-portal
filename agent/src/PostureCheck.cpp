#define INITGUID // MinGW's libuuid.a doesn't carry CLSID_NetFwPolicy2's data -
                 // this makes DEFINE_GUID in netfw.h emit a real (selectany,
                 // safely-mergeable) definition in this translation unit
                 // instead of just an extern declaration with nothing to link.
#include "PostureCheck.h"
#include <windows.h>
#include <netfw.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>

#pragma comment(lib, "wbemuuid.lib")

bool PostureCheck::isFirewallEnabled() {
    INetFwPolicy2* policy = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_NetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
        IID_INetFwPolicy2, (void**)&policy);

    if (FAILED(hr) || !policy) {
        std::cerr << "[Agent] Firewall check failed (COM error 0x" << std::hex << hr << "), assuming disabled" << std::endl;
        return false;
    }

    long currentProfiles = 0;
    policy->get_CurrentProfileTypes(&currentProfiles);

    NET_FW_PROFILE_TYPE2 profileToCheck = NET_FW_PROFILE2_PRIVATE;
    if (currentProfiles & NET_FW_PROFILE2_DOMAIN) profileToCheck = NET_FW_PROFILE2_DOMAIN;
    else if (currentProfiles & NET_FW_PROFILE2_PRIVATE) profileToCheck = NET_FW_PROFILE2_PRIVATE;
    else if (currentProfiles & NET_FW_PROFILE2_PUBLIC) profileToCheck = NET_FW_PROFILE2_PUBLIC;

    VARIANT_BOOL enabled = VARIANT_FALSE;
    policy->get_FirewallEnabled(profileToCheck, &enabled);
    policy->Release();

    return enabled == VARIANT_TRUE;
}

bool PostureCheck::isAntivirusPresent() {
    IWbemLocator* locator = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&locator);
    if (FAILED(hr) || !locator) {
        std::cerr << "[Agent] WMI locator creation failed (0x" << std::hex << hr << "), assuming no AV" << std::endl;
        return false;
    }

    IWbemServices* services = nullptr;
    hr = locator->ConnectServer(_bstr_t(L"ROOT\\SecurityCenter2"), nullptr, nullptr,
        nullptr, 0, nullptr, nullptr, &services);
    if (FAILED(hr) || !services) {
        locator->Release();
        std::cerr << "[Agent] WMI SecurityCenter2 connection failed (0x" << std::hex << hr << "), assuming no AV" << std::endl;
        return false;
    }

    hr = CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        services->Release();
        locator->Release();
        return false;
    }

    IEnumWbemClassObject* enumerator = nullptr;
    hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT * FROM AntiVirusProduct"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);

    bool found = false;
    if (SUCCEEDED(hr) && enumerator) {
        IWbemClassObject* obj = nullptr;
        ULONG returned = 0;
        if (enumerator->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK && returned > 0) {
            found = true;
            obj->Release();
        }
        enumerator->Release();
    }

    services->Release();
    locator->Release();
    return found;
}
