#include <windows.h>
#include <gdiplus.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

// Link to GDI+ library
#pragma comment (lib,"Gdiplus.lib")

struct ScreenShot {
    BYTE* data;
    size_t size;
};

// Initialize GDI+
void InitializeGDIPlus() {
    Gdiplus::GdiplusStartupInput gdiPlusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiPlusStartupInput, nullptr);
}

// Function to take a screenshot and return bytes
ScreenShot Screenshot(int width, int height, std::string windowTitle, const std::string& format) {
    // Initialize GDI+

    InitializeGDIPlus();

    HWND hwnd = FindWindowA(nullptr, windowTitle.c_str());

    HDC hdcWindow = GetDC(hwnd);
    HDC hdcMemDC = CreateCompatibleDC(hdcWindow);

    if (width == 0) {
        width = GetDeviceCaps(hdcWindow, HORZRES);
    }

    if (height == 0) {
        height = GetDeviceCaps(hdcWindow, VERTRES);
    }

    // Create a compatible bitmap for the given width and height
    HBITMAP hbmScreen = CreateCompatibleBitmap(hdcWindow, width, height);

    // Select the bitmap into memory device context
    SelectObject(hdcMemDC, hbmScreen);

    // Bit block transfer into our compatible memory DC
    BitBlt(hdcMemDC, 0, 0, width, height, hdcWindow, 0, 0, SRCCOPY);

    // Initialize GDI+
    Gdiplus::Bitmap bitmap(hbmScreen, nullptr);

    // Save screenshot to memory (use PNG format for compression)
    IStream* stream = nullptr;
    CreateStreamOnHGlobal(nullptr, TRUE, &stream);
    CLSID clsid;
    if (format == "png") {
        CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // PNG CLSID
    }
    else if (format == "bmp") {
        CLSIDFromString(L"{557CF401-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // BMP CLSID
    }
    else if (format == "jpeg" || format == "jpg") {
        CLSIDFromString(L"{557CF401-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // JPEG CLSID
    }
    else if (format == "gif") {
        CLSIDFromString(L"{557CF402-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // GIF CLSID
    }
    else if (format == "tiff" || format == "tif") {
        CLSIDFromString(L"{557CF405-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // TIFF CLSID
    }
    else if (format == "exif") {
        CLSIDFromString(L"{557CF404-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // EXIF CLSID
    }
    else if (format == "wmf") {
        CLSIDFromString(L"{557CF407-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // WMF CLSID
    }
    else if (format == "emf") {
        CLSIDFromString(L"{557CF408-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // EMF CLSID
    }
    else {
        // Default to PNG if unknown format
        CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &clsid);  // PNG CLSID
        
    }

    // Save the bitmap to the stream
    bitmap.Save(stream, &clsid, nullptr);

    // Get the size of the screenshot
    STATSTG statstg;
    stream->Stat(&statstg, STATFLAG_DEFAULT);
    size_t size = statstg.cbSize.LowPart;

    // Allocate raw memory buffer for the screenshot
    BYTE* data = new BYTE[size];

    // Read the screenshot data into the byte array
    LARGE_INTEGER liZero = {};
    stream->Seek(liZero, STREAM_SEEK_SET, nullptr);
    stream->Read(data, size, nullptr);

    // Clean up
    DeleteObject(hbmScreen);
    DeleteDC(hdcMemDC);
    ReleaseDC(hwnd, hdcWindow);
    stream->Release();

    ScreenShot screenshot;
    screenshot.data = data;
    screenshot.size = size;

    return screenshot; // Return raw pointer to the byte array
}

// Function to save the screenshot bytes to a .png file
void SaveToFile(const std::string& filename, ScreenShot screenshot, ULONG size) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not create file " << filename << std::endl;
        return;
    }
    file.write(reinterpret_cast<const char*>(screenshot.data), size);
    file.close();
    std::cout << "Screenshot saved to " << filename << std::endl;
}

HWND StringToHWND(const std::string& input) {
    std::istringstream ss(input);
    long long handle;
    if (ss >> std::hex >> handle) {
        return reinterpret_cast<HWND>(handle);
    }
    return nullptr; // Invalid input
}

int main() {
    std::string windowTitle;
    std::cout << "Enter the window title: ";
    std::getline(std::cin, windowTitle);

    ScreenShot screenshot;

    screenshot = Screenshot(0, 0, windowTitle, "png");

    std::cout << screenshot.size << std::endl;

    SaveToFile("screenshot.png", screenshot, screenshot.size);

    return 0;
}
