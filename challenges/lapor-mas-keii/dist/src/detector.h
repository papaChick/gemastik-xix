#ifndef DETECTOR_H
#define DETECTOR_H

#include <stddef.h>

int  detector_load(const char *bin_path, const char *conf_path);
int  detector_threshold(void);
int  detector_score(const char *text, size_t n);
int  detector_is_clean(const char *text, size_t n);

#endif
