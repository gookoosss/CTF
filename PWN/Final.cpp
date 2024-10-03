
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <png.h>
#include <stdio.h>
#include <stdlib.h>

void save_image_as_png(XImage *image, const char *filename) {
    int width = image->width;
    int height = image->height;

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open file for writing: %s\n", filename);
        return;
    }

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) {
        fprintf(stderr, "Failed to create PNG write struct\n");
        fclose(fp);
        return;
    }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        fprintf(stderr, "Failed to create PNG info struct\n");
        png_destroy_write_struct(&png, NULL);
        fclose(fp);
        return;
    }

    if (setjmp(png_jmpbuf(png))) {
        fprintf(stderr, "Error during PNG creation\n");
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        return;
    }

    png_init_io(png, fp);

    // Output PNG header
    png_set_IHDR(
        png, info, width, height,
        8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT
    );
    png_write_info(png, info);

    // Allocate row pointers
    png_bytep row = (png_bytep)malloc(3 * width * sizeof(png_byte));
    if (!row) {
        fprintf(stderr, "Failed to allocate memory for row\n");
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        return;
    }

    // Write image data
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            unsigned long pixel = XGetPixel(image, x, y);
            unsigned char blue = pixel & 0xff;
            unsigned char green = (pixel >> 8) & 0xff;
            unsigned char red = (pixel >> 16) & 0xff;

            row[x * 3] = red;
            row[x * 3 + 1] = green;
            row[x * 3 + 2] = blue;
        }
        png_write_row(png, row);
    }

    // End write
    png_write_end(png, NULL);

    // Free resources
    free(row);
    png_destroy_write_struct(&png, &info);
    fclose(fp);

    printf("Saved image to: %s\n", filename);
}

void capture_window(Display *display, Window win, const char *filename) {
    XWindowAttributes attr;

    // Get window attributes, check if it’s viewable (mapped)
    if (XGetWindowAttributes(display, win, &attr) == 0 || attr.map_state != IsViewable) {
        // Skip windows that aren't viewable (e.g., minimized or hidden)
        return;
    }

    int width = attr.width;
    int height = attr.height;

    // Only capture windows with a valid drawable area
    if (width == 0 || height == 0) {
        return;
    }

    // Attempt to capture the window image
    XImage *image = XGetImage(display, win, 0, 0, width, height, AllPlanes, ZPixmap);
    if (!image) {
        fprintf(stderr, "Failed to capture window content for window: 0x%lx\n", win);
        return;
    }

    // Save the captured image as a PNG
    save_image_as_png(image, filename);

    XDestroyImage(image);
}

int main(){

    Display *display = XOpenDisplay(NULL);
    if (!display) {
        fprintf(stderr, "Unable to open X display\n");
        return 1;
    }

    capture_window(display, 0x600006, "window.png");

    XCloseDisplay(display);
    return 0;
}
