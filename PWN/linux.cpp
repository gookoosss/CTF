#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unordered_set>

std::string getValueFromFile(const std::string &filePath, const std::string &key) {
    std::ifstream file(filePath);
    std::string line, value;
    
    if (file.is_open()) {
        while (std::getline(file, line)) {
            if (line.find(key) != std::string::npos) {
                std::istringstream iss(line);
                iss >> value >> value; // Skip key and take the value
                return value;
            }
        }
    }
    return "Not found";
}

int getCpuCount() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    int count = 0;
    while (std::getline(cpuinfo, line)) {
        if (line.find("processor") != std::string::npos) {
            count++;
        }
    }
    return count;
}

int getCoresPerSocket() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    int coresPerSocket = 0;
    while (std::getline(cpuinfo, line)) {
        if (line.find("cpu cores") != std::string::npos) {
            std::stringstream ss(line.substr(line.find(":") + 2));
            ss >> coresPerSocket;
            break;
        }
    }
    return coresPerSocket;
}

int getThreadsPerCore() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    int threadsPerCore = 0;
    int coresPerSocket = getCoresPerSocket();
    
    // Count how many unique physical cores are represented.
    std::unordered_set<int> uniqueCoreIDs;
    
    while (std::getline(cpuinfo, line)) {
        if (line.find("core id") != std::string::npos) {
            std::stringstream ss(line.substr(line.find(":") + 2));
            int coreID;
            ss >> coreID;
            uniqueCoreIDs.insert(coreID);
        }
    }

    // Threads per core is calculated as total CPUs / physical cores
    int cpuCount = getCpuCount();
    if (!uniqueCoreIDs.empty()) {
        threadsPerCore = cpuCount / uniqueCoreIDs.size();
    } else {
        // If "core id" is not available, we assume threads per core as total CPUs / cores per socket
        threadsPerCore = cpuCount / coresPerSocket;
    }

    return threadsPerCore;
}

std::string getCpuInfo(const std::string &key) {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    
    while (std::getline(cpuinfo, line)) {
        if (line.find(key) != std::string::npos) {
            return line.substr(line.find(":") + 2); // Extract value after ": "
        }
    }
    return "Not found";
}

int getSocketCount() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    std::unordered_set<int> uniquePhysicalIDs;

    // Parse the `physical id` field to get unique socket IDs
    while (std::getline(cpuinfo, line)) {
        if (line.find("physical id") != std::string::npos) {
            std::stringstream ss(line.substr(line.find(":") + 2));
            int physicalID;
            ss >> physicalID;
            uniquePhysicalIDs.insert(physicalID);
        }
    }

    // Return the number of unique physical IDs, i.e., the number of sockets
    return uniquePhysicalIDs.size();
}

int main() {
    // Architecture information
    std::cout << "Architecture: ";
    if (sizeof(void *) == 8) {
        std::cout << "x86_64" << std::endl;
        std::cout << "CPU op-mode(s): 32-bit, 64-bit" << std::endl;
    } else if (sizeof(void *) == 4) {
        std::cout << "x86" << std::endl;
        std::cout << "CPU op-mode(s): 32-bit" << std::endl;
    }
    
    // Address sizes (this requires more detailed parsing of /proc/cpuinfo or sysctl)
    std::cout << "Address sizes: " << getCpuInfo("address sizes") << std::endl;
    
    // Byte Order (Assuming little endian for most architectures)
    std::cout << "Byte Order: Little Endian" << std::endl;

    // CPU(s) count
    std::cout << "CPU(s): " << getCpuCount() << std::endl;
    
    // On-line CPU(s) list (hardcoding a basic check here for simplicity)
    std::cout << "On-line CPU(s) list: 0-" << getCpuCount() - 1 << std::endl;
    
    // Vendor ID and Model name
    std::cout << "Vendor ID: " << getCpuInfo("vendor_id") << std::endl;
    std::cout << "Model name: " << getCpuInfo("model name") << std::endl;
    
    // CPU family and Model
    std::cout << "CPU family: " << getCpuInfo("cpu family") << std::endl;
    std::cout << "Model: " << getCpuInfo("model") << std::endl;
    
    // Thread(s) per core and Core(s) per socket (Assuming hyper-threading enabled)
    std::cout << "Thread(s) per core: " << getThreadsPerCore() << std::endl;
    std::cout << "Core(s) per socket: " << getCpuInfo("cpu cores") << std::endl;
    
    // Socket(s)
    std::cout << "Socket(s): "<< getSocketCount() << std::endl;  // Assuming 1 socket for simplicity
    
    // Stepping, BogoMIPS, and Flags
    std::cout << "Stepping: " << getCpuInfo("stepping") << std::endl;
    std::cout << "BogoMIPS: " << getCpuInfo("bogomips") << std::endl;
    std::cout << "Flags: " << getCpuInfo("flags") << std::endl;

    // Virtualization information
    std::cout << "Virtualization: " << (getCpuInfo("flags").find("vmx") != std::string::npos ? "VT-x" : "Not available") << std::endl;
    
    // Cache information (Assuming reading from the first CPU's cache)
    std::cout << "Caches (sum of all):" << std::endl;
    std::cout << "  L1d: " << getValueFromFile("/sys/devices/system/cpu/cpu0/cache/index0/size", "") << std::endl;
    std::cout << "  L1i: " << getValueFromFile("/sys/devices/system/cpu/cpu0/cache/index1/size", "") << std::endl;
    std::cout << "  L2: " << getValueFromFile("/sys/devices/system/cpu/cpu0/cache/index2/size", "") << std::endl;
    std::cout << "  L3: " << getValueFromFile("/sys/devices/system/cpu/cpu0/cache/index3/size", "") << std::endl;

    return 0;
}

