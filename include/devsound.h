#ifndef DEVAUDIO_H
#define DEVAUDIO_H

/*
 * Marrow Audio Device Interface
 * /dev/audio - Audio output device (9front compatible)
 */

#include <stddef.h>
#include <stdint.h>

/*
 * Audio parameters
 */
#define SOUND_SAMPLE_RATE     44100
#define SOUND_BIT_DEPTH       16
#define SOUND_MAX_CHANNELS    2
#define SOUND_BUFFER_SIZE     4096

/*
 * Sound device state
 */
typedef struct {
    short buffer[SOUND_BUFFER_SIZE];
    size_t buffer_len;
    int is_playing;
    int channels;
    /* Backend handle (ALSA) */
    void *alsa_handle;
} SoundState;

/*
 * Control commands
 */
#define SOUND_CTL_START      "start"
#define SOUND_CTL_STOP       "stop"
#define SOUND_CTL_SET_CHAN   "chan "
#define SOUND_CTL_GET_STATUS "status"

/*
 * Device initialization
 */
int devaudio_init(P9Node *dev_dir);

/*
 * 9P read/write handlers
 * /dev/audio - main audio data stream (compatible with 9front)
 */
ssize_t devaudio_read(char *buf, size_t count, uint64_t offset);
ssize_t devaudio_write(const char *buf, size_t count, uint64_t offset);

/*
 * Control file handlers (optional extensions)
 * /dev/audioctl - audio control interface
 */
ssize_t devaudioctl_read(char *buf, size_t count, uint64_t offset);
ssize_t devaudioctl_write(const char *buf, size_t count, uint64_t offset);

/*
 * Volume control (9front style)
 */
int devaudio_set_volume(int left, int right);
void devaudio_get_volume(int *left, int *right);

#endif /* DEVAUDIO_H */
