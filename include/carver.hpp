#ifndef CARVER_HPP
#define CARVER_HPP

#include <string>
#include <vector>

/* Image stream embedded inside a larger file */
struct Carved
{
    std::string type;  /* jpeg, png, heic, mov, mp4 */
    size_t offset = 0, size = 0;
    unsigned width = 0, height = 0;  /* 0 when the format carries no easily parsed dimensions */
};

/* Complete, structurally valid JPEG/PNG/HEIC/MOV/MP4 streams inside data; a stream that is the whole data is skipped */
std::vector<Carved> carve_images(const std::string& data);

/* Photo-like file names (IMG_1234.HEIC, ...) in raw bytes, a heuristic */
std::vector<std::string> photo_names(const std::string& data);

#endif
