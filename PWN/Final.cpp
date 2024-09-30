#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <cairo/cairo.h>
#include <cairo/cairo-xlib.h>
#include <iostream>
#include <fstream>
#include <string>

// Structure to hold screenshot data
struct ScreenShot {
    unsigned char* data;
    int width, height;
};

// Function to capture a screenshot on Linux using X11 and Cairo
ScreenShot Screenshot(int width, int height, const std::string& windowTitle) {
    // Open a connection to the X server
    Display* display = XOpenDisplay(nullptr);
    if (!display) {
        std::cerr << "Error: Cannot open display." << std::endl;
        exit(1);
    }

    // Get the root window (entire screen)
    Window root = DefaultRootWindow(display);

    // Get screen dimensions if width and height are not provided
    if (width == 0 || height == 0) {
        Screen* screen = DefaultScreenOfDisplay(display);
        width = screen->width;
        height = screen->height;
    }

    // Capture image using X11
    XImage* image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);

    // Create a Cairo surface from the X11 image
    cairo_surface_t* surface = cairo_image_surface_create_for_data(
        reinterpret_cast<unsigned char*>(image->data), 
        CAIRO_FORMAT_RGB24, 
        width, 
        height, 
        image->bytes_per_line);

    // Copy the screenshot data into our structure
    ScreenShot screenshot;
    screenshot.data = cairo_image_surface_get_data(surface);
    screenshot.width = width;
    screenshot.height = height;

    // Free the X11 image
    XDestroyImage(image);

    // Close the connection to the X server
    XCloseDisplay(display);

    return screenshot;
}

// Function to save the screenshot as a PNG file using Cairo
void SaveToFile(const std::string& filename, ScreenShot screenshot) {
    cairo_surface_t* surface = cairo_image_surface_create_for_data(
        screenshot.data, CAIRO_FORMAT_RGB24, screenshot.width, screenshot.height, screenshot.width * 4);

    // Save the surface to a PNG file
    cairo_surface_write_to_png(surface, filename.c_str());

    cairo_surface_destroy(surface);

    std::cout << "Screenshot saved to " << filename << std::endl;
}

int main() {
    std::string windowTitle;
    std::cout << "Enter the window title (ignored on Linux): ";
    std::getline(std::cin, windowTitle);

    // Take screenshot
    ScreenShot screenshot = Screenshot(0, 0, windowTitle);

    // Save to file
    SaveToFile("screenshot.png", screenshot);

    return 0;
}
