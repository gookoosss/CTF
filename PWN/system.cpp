#include <iostream>
#include <Windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <ctime>
#include <sstream>
#pragma comment(lib, "wbemuuid.lib")

void initializeCOM() {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cout << "Failed to initialize COM library. Error code = 0x"
            << std::hex << hres << std::endl;
        exit(1);
    }
}

void initializeSecurity() {
    HRESULT hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,    // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE,  // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres)) {
        std::cout << "Failed to initialize security. Error code = 0x"
            << std::hex << hres << std::endl;
        CoUninitialize();
        exit(1);
    }
}

IWbemLocator* createWbemLocator() {
    IWbemLocator* pLoc = NULL;

    HRESULT hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        std::cout << "Failed to create IWbemLocator object. "
            << "Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        exit(1);
    }

    return pLoc;
}

IWbemServices* connectWMI(IWbemLocator* pLoc) {
    IWbemServices* pSvc = NULL;

    HRESULT hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags
        0,                       // Authority
        0,                       // Context object
        &pSvc                    // IWbemServices proxy
    );

    if (FAILED(hres)) {
        std::cout << "Could not connect to WMI. Error code = 0x"
            << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        exit(1);
    }

    return pSvc;
}

void setProxySecurity(IWbemServices* pSvc) {
    HRESULT hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // Client identity
        EOAC_NONE                    // Proxy capabilities 
    );

    if (FAILED(hres)) {
        std::cout << "Could not set proxy blanket. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }
}

std::string convertWMItoDateTime(const std::wstring& wmiDate) {
    if (wmiDate.length() < 14) return "N/A";

    // Extract year, month, day, hour, minute, second from the WMI datetime string
    int year, month, day, hour, minute, second;
    std::wstringstream(wmiDate.substr(0, 4)) >> year;
    std::wstringstream(wmiDate.substr(4, 2)) >> month;
    std::wstringstream(wmiDate.substr(6, 2)) >> day;
    std::wstringstream(wmiDate.substr(8, 2)) >> hour;
    std::wstringstream(wmiDate.substr(10, 2)) >> minute;
    std::wstringstream(wmiDate.substr(12, 2)) >> second;

    // Adjust year to be relative to 1900 (for struct tm)
    year -= 1900;

    // Create a tm structure for formatting
    std::tm timeinfo = {};
    timeinfo.tm_year = year;
    timeinfo.tm_mon = month - 1;
    timeinfo.tm_mday = day;
    timeinfo.tm_hour = hour;
    timeinfo.tm_min = minute;
    timeinfo.tm_sec = second;

    // Format the time into a human-readable string
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);

    return buffer;
}

void querySystemInfo(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for operating system failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        hr = pclsObj->Get(L"CSName", 0, &vtProp, 0, 0);
        std::wcout << "Host Name: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // OS Name
        hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
        std::wcout << "OS Name: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // OS Version
        hr = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
        std::wcout << "OS Version: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // OS Manufacturer
        hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
        std::wcout << "OS Manufacturer: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // OS Configuration
        hr = pclsObj->Get(L"OSConfiguration", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::wcout << "OS Configuration: " << vtProp.bstrVal << std::endl;
        }
        VariantClear(&vtProp);

        // OS Build Type
        hr = pclsObj->Get(L"BuildType", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::wcout << "OS Build Type: " << vtProp.bstrVal << std::endl;
        }
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"RegisteredUser", 0, &vtProp, 0, 0);
        std::wcout << "Registered Owner: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // Registered Organization
       /* hr = pclsObj->Get(L"Organization", 0, &vtProp, 0, 0);
        std::wcout << "Registered Organization: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);*/

        // Product ID
        hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        std::wcout << "Product ID: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // Original Install Date
        hr = pclsObj->Get(L"InstallDate", 0, &vtProp, 0, 0);
        std::cout << "Original Install Date: " << convertWMItoDateTime(vtProp.bstrVal) << std::endl;
        VariantClear(&vtProp);

        // System Boot Time
        hr = pclsObj->Get(L"LastBootUpTime", 0, &vtProp, 0, 0);
        std::cout << "System Boot Time: " << convertWMItoDateTime(vtProp.bstrVal) << std::endl;
        VariantClear(&vtProp);


        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}

void queryComputerInfo(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_ComputerSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for computer system failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        // System Manufacturer
        hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
        std::wcout << "System Manufacturer: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // System Model
        hr = pclsObj->Get(L"Model", 0, &vtProp, 0, 0);
        std::wcout << "System Model: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // System Type
        hr = pclsObj->Get(L"SystemType", 0, &vtProp, 0, 0);
        std::wcout << "System Type: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}

void queryProcessorInfo(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for processor information failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        // Processor(s)
        hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        std::wcout << "Processor(s): " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}

void queryBIOSInfo(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_BIOS"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for processor information failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        // Processor(s)
        hr = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
        std::wcout << "BIOS Version: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}

void queryOSDirectories(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for OS directories failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        hr = pclsObj->Get(L"WindowsDirectory", 0, &vtProp, 0, 0);
        std::wcout << "Windows Directory: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"SystemDirectory", 0, &vtProp, 0, 0);
        std::wcout << "System Directory: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}

void querySystemDetails(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for system details failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        hr = pclsObj->Get(L"BootDevice", 0, &vtProp, 0, 0);
        std::wcout << "Boot Device: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"Locale", 0, &vtProp, 0, 0);
        std::wcout << "System Locale: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"OSArchitecture", 0, &vtProp, 0, 0);
        std::wcout << "System Type: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}

void queryTimeZoneInfo(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_TimeZone"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for time zone info failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
        std::wcout << "Time Zone: " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}

std::wstring formatWithCommas(long long value) {
    std::wstringstream ss;
    ss.imbue(std::locale("")); // Set locale for formatting
    ss << std::fixed << value;
    return ss.str(); // Return as wstring
}

void queryMemoryInfo(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cout << "Query for memory information failed. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        CoUninitialize();
        exit(1);
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        // Total Physical Memory (KB)
        hr = pclsObj->Get(L"TotalVisibleMemorySize", 0, &vtProp, 0, 0);
        long long totalPhysMemKB = vtProp.ulVal; // in KB
        long long totalPhysMemMB = totalPhysMemKB / 1024; // Convert to MB
        std::wcout << L"Total Physical Memory:     " << formatWithCommas(totalPhysMemMB) << L" MB" << std::endl;
        VariantClear(&vtProp);

        // Available Physical Memory (KB)
        hr = pclsObj->Get(L"FreePhysicalMemory", 0, &vtProp, 0, 0);
        long long freePhysMemKB = vtProp.ulVal; // in KB
        long long freePhysMemMB = freePhysMemKB / 1024; // Convert to MB
        std::wcout << L"Available Physical Memory: " << formatWithCommas(freePhysMemMB) << L" MB" << std::endl;
        VariantClear(&vtProp);

        // Total Virtual Memory (KB)
        hr = pclsObj->Get(L"TotalVirtualMemorySize", 0, &vtProp, 0, 0);
        long long totalVirtMemKB = vtProp.ulVal; // in KB
        long long totalVirtMemMB = totalVirtMemKB / 1024; // Convert to MB
        std::wcout << L"Virtual Memory: Max Size:  " << formatWithCommas(totalVirtMemMB) << L" MB" << std::endl;
        VariantClear(&vtProp);

        // Available Virtual Memory (KB)
        hr = pclsObj->Get(L"FreeVirtualMemory", 0, &vtProp, 0, 0);
        long long freeVirtMemKB = vtProp.ulVal; // in KB
        long long freeVirtMemMB = freeVirtMemKB / 1024; // Convert to MB
        std::wcout << L"Virtual Memory: Available: " << formatWithCommas(freeVirtMemMB) << L" MB" << std::endl;
        VariantClear(&vtProp);

        // Virtual Memory In Use: (Total Virtual Memory - Free Virtual Memory)
        long long virtMemInUseMB = totalVirtMemMB - freeVirtMemMB;
        std::wcout << L"Virtual Memory: In Use:    " << formatWithCommas(virtMemInUseMB) << L" MB" << std::endl;

        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
}


int main() {
    // Initialize COM
    initializeCOM();

    // Initialize security
    initializeSecurity();

    // Obtain the initial locator to WMI 
    IWbemLocator* pLoc = createWbemLocator();

    // Connect to WMI 
    IWbemServices* pSvc = connectWMI(pLoc);

    // Set security levels on the proxy
    setProxySecurity(pSvc);

    // Query system information
    querySystemInfo(pSvc);



    // Obtain the initial locator to WMI 
    //pLoc = createWbemLocator();

    // Connect to WMI 
    pSvc = connectWMI(pLoc);

    // Query computer system information
    queryComputerInfo(pSvc);

    pSvc = connectWMI(pLoc);

    // Query processor information
    queryProcessorInfo(pSvc);

    pSvc = connectWMI(pLoc);

    queryBIOSInfo(pSvc);

    pSvc = connectWMI(pLoc);

    queryOSDirectories(pSvc);

    pSvc = connectWMI(pLoc);

    querySystemDetails(pSvc);

    pSvc = connectWMI(pLoc);

    queryTimeZoneInfo(pSvc);

    pSvc = connectWMI(pLoc);

    queryMemoryInfo(pSvc);
    // Cleanup
    pLoc->Release();
    CoUninitialize();

    return 0;
}
