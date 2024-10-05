#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <iostream>
#include <iomanip> // Include this header for std::hex


Window list_and_capture_windows(Display *display, Window root, std::string windowTitle) {
    Window parent, *children;
    unsigned int nchildren;
    Window targetWindow;
    char* name = nullptr;

    // Query the tree of windows
    if (XQueryTree(display, root, &root, &parent, &children, &nchildren)) {
        for (unsigned int i = 0; i < nchildren; i++) {
            // Only capture top-level windows (not dialog boxes, etc.)
            if (children[i] != root) {
                char* name = nullptr;
                if (XFetchName(display, children[i], &name)) {
                    // Print the window name and ID in hexadecimal format
                    std::cout << "Window ID: 0x" << std::hex << children[i] << ", Name: " << (name ? name : "Unnamed") << std::endl;
                    
                } else {
                    std::cout << "Window ID: 0x" << std::hex << children[i] << ", Name: Unnamed" << std::endl;
                }

                if (name && windowTitle == name) {
                    targetWindow = children[i];
                    XFree(name);
                    XFree(children);
                    std::cout << "----------------------DONE----------------------\n";

                    return targetWindow;
                }

                XFree(name);


                Window parent2, *children2;
                unsigned int nchildren2;

                std::cout << "----------------------Child----------------------\n";
                if (XQueryTree(display, children[i], &children[i], &parent2, &children2, &nchildren2)) {
                    for (unsigned int j = 0; j < nchildren2; j++) { // Changed loop variable to j
                        // Only capture top-level windows (not dialog boxes, etc.)
                        if (children2[j] != root) {
                            
                            if (XFetchName(display, children2[j], &name)) {
                                // Print the window name and ID in hexadecimal format
                                std::cout << "Window ID: 0x" << std::hex << children2[j] << ", Name: " << (name ? name : "Unnamed") << std::endl;
                                
                            } else {
                                std::cout << "Window ID: 0x" << std::hex << children2[j] << ", Name: Unnamed" << std::endl;
                            }
                        }

                        if (name && windowTitle == name) {
                            targetWindow = children2[j];
                            XFree(children);
                            XFree(children2);
                            XFree(name);
                            std::cout << "----------------------DONE----------------------\n";
                            return targetWindow;
                        }

                        XFree(name);

                    }

                    if (children2) {
                        XFree(children2);
                    }
                }

                std::cout << "----------------------END----------------------\n";
            }
        }
        if (children) {
            XFree(children);
        }
    } else {
        std::cerr << "Failed to query the window tree." << std::endl;
    }
    return 0;
}


int main() {
    Display *display = XOpenDisplay(nullptr);
    if (display == nullptr) {
        std::cerr << "Unable to open X display." << std::endl;
        return 1;
    }

    Window root = DefaultRootWindow(display);
    Window targetWindow = list_and_capture_windows(display, root, "Mozilla Firefox");
    std::cout << "Window ID: 0x" << std::hex << targetWindow << std::endl;

    XCloseDisplay(display);
    return 0;
}
