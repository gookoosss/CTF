```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <png.h>
#include <iostream>
#include <string>
#include <cstdlib>

// Function to save the image in PNG format
void SaveToPNG(const std::string& filename, unsigned char* data, int width, int height) {
    FILE *fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        std::cerr << "Error: Could not create file " << filename << std::endl;
        return;
    }

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png) {
        std::cerr << "Error: png_create_write_struct failed" << std::endl;
        fclose(fp);
        return;
    }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        std::cerr << "Error: png_create_info_struct failed" << std::endl;
        png_destroy_write_struct(&png, nullptr);
        fclose(fp);
        return;
    }

    if (setjmp(png_jmpbuf(png))) {
        std::cerr << "Error: PNG write error" << std::endl;
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        return;
    }

    png_init_io(png, fp);

    // Correct the argument order in png_set_IHDR
    png_set_IHDR(png, info, width, height, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

    png_write_info(png, info);

    png_bytep row = new png_byte[3 * width];
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            row[x * 3 + 0] = data[(y * width + x) * 4 + 0]; // R
            row[x * 3 + 1] = data[(y * width + x) * 4 + 1]; // G
            row[x * 3 + 2] = data[(y * width + x) * 4 + 2]; // B
        }
        png_write_row(png, row);
    }

    delete[] row;
    png_write_end(png, nullptr);
    png_destroy_write_struct(&png, &info);
    fclose(fp);
}

// Function to capture the screen and return the image data
unsigned char* CaptureScreen(int& width, int& height) {
    Display* display = XOpenDisplay(nullptr);
    if (!display) {
        std::cerr << "Error: Unable to open display" << std::endl;
        return nullptr;
    }

    Window root = DefaultRootWindow(display);
    XWindowAttributes rootAttributes;
    XGetWindowAttributes(display, root, &rootAttributes);

    width = rootAttributes.width;
    height = rootAttributes.height;

    XImage* image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
    if (!image) {
        std::cerr << "Error: Unable to get image" << std::endl;
        XCloseDisplay(display);
        return nullptr;
    }

    unsigned char* data = new unsigned char[width * height * 4];
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            long pixel = XGetPixel(image, x, y);
            data[(y * width + x) * 4 + 0] = (pixel & image->red_mask) >> 16; // R
            data[(y * width + x) * 4 + 1] = (pixel & image->green_mask) >> 8; // G
            data[(y * width + x) * 4 + 2] = (pixel & image->blue_mask); // B
            data[(y * width + x) * 4 + 3] = 255; // Alpha
        }
    }

    XDestroyImage(image);
    XCloseDisplay(display);
    return data;
}

int main() {
    int width, height;
    unsigned char* data = CaptureScreen(width, height);
    if (!data) {
        return 1;
    }

    std::string filename = "screenshot.png";
    SaveToPNG(filename, data, width, height);
    std::cout << "Screenshot saved to " << filename << std::endl;

    delete[] data;
    return 0;
}

```
