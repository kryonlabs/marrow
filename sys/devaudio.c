/*
 * Marrow Audio Device Implementation
 * /dev/audio - Audio output via ALSA or Plan 9 audio (9front compatible)
 * C99 compliant (C89 with alloca extension)
 *
 * 9front audio compatibility:
 * - /dev/audio - 16-bit little-endian PCM, stereo, 44100 Hz
 * - Writes play audio immediately
 * - /dev/audioctl - control interface (volume, etc)
 *
 * Supports dual backend:
 * - ALSA on Linux
 * - /dev/audio on Plan 9
 */

#include "lib9p.h"
#include <lib9.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>

#define _GNU_SOURCE  /* For alloca */
#include <alloca.h>

#ifdef USE_ALSA
#define ALSA_PCM_NEW_HW_PARAMS_API
#include <alsa/asoundlib.h>
#endif

#ifdef USE_PLAN9_AUDIO
/* Plan 9 audio uses standard POSIX I/O */
#endif

#include "devsound.h"

/*
 * Global audio device state
 * 9front uses unsigned char volume 0-100
 */
static SoundState g_audio_state;
#ifdef USE_ALSA
static snd_pcm_t *g_pcm_handle = NULL;
#endif
#ifdef USE_PLAN9_AUDIO
static int g_plan9_audio_fd = -1;
#endif
static int g_volume_left = 75;   /* Default volume 0-100 */
static int g_volume_right = 75;
static int g_audio_initialized = 0;

/*
 * Apply volume to samples (16-bit PCM)
 * 9front-style volume: 0-100
 */
static void apply_volume(short *samples, int frame_count, int channels)
{
    int i;
    double scale_left = (double)g_volume_left / 100.0;
    double scale_right = (double)g_volume_right / 100.0;

    for (i = 0; i < frame_count; i++) {
        /* Left channel */
        samples[i * channels] = (short)(samples[i * channels] * scale_left);
        if (channels >= 2) {
            /* Right channel */
            samples[i * channels + 1] = (short)(samples[i * channels + 1] * scale_right);
        }
    }
}

/*
 * Initialize audio device (stereo by default for 9front compatibility)
 * Supports both ALSA (Linux) and Plan 9 /dev/audio
 */
static int init_audio(int channels)
{
#ifdef USE_ALSA
    int err;
    int dir = 0;
    snd_pcm_uframes_t frames = SOUND_BUFFER_SIZE;
    unsigned int actual_rate;
    snd_pcm_hw_params_t *params;
    int ok;

    if (g_pcm_handle != NULL) {
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
    }

    /* Open PCM device */
    err = snd_pcm_open(&g_pcm_handle, "default",
                       SND_PCM_STREAM_PLAYBACK, 0);
    if (err < 0) {
        fprintf(stderr, "devaudio: cannot open audio: %s\n",
                snd_strerror(err));
        return -1;
    }

    /* Allocate parameters - use malloc instead of alloca for C99 compatibility */
    params = malloc(snd_pcm_hw_params_sizeof());
    if (params == NULL) {
        fprintf(stderr, "devaudio: cannot allocate hw params\n");
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
        return -1;
    }

    /* Initialize params */
    snd_pcm_hw_params_any(g_pcm_handle, params);

    /* Set parameters */
    ok = snd_pcm_hw_params_set_access(g_pcm_handle, params,
                                  SND_PCM_ACCESS_RW_INTERLEAVED);
    if (ok < 0) {
        fprintf(stderr, "devaudio: cannot set access: %s\n",
                snd_strerror(ok));
        free(params);
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
        return -1;
    }

    ok = snd_pcm_hw_params_set_format(g_pcm_handle, params,
                                  SND_PCM_FORMAT_S16_LE);
    if (ok < 0) {
        fprintf(stderr, "devaudio: cannot set format: %s\n",
                snd_strerror(ok));
        free(params);
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
        return -1;
    }

    ok = snd_pcm_hw_params_set_channels(g_pcm_handle, params, channels);
    if (ok < 0) {
        fprintf(stderr, "devaudio: cannot set channels: %s\n",
                snd_strerror(ok));
        free(params);
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
        return -1;
    }

    actual_rate = SOUND_SAMPLE_RATE;
    ok = snd_pcm_hw_params_set_rate_near(g_pcm_handle, params,
                                     &actual_rate, &dir);
    if (ok < 0) {
        fprintf(stderr, "devaudio: cannot set rate: %s\n",
                snd_strerror(ok));
        free(params);
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
        return -1;
    }

    frames = SOUND_BUFFER_SIZE / channels;
    ok = snd_pcm_hw_params_set_period_size_near(g_pcm_handle, params,
                                            &frames, &dir);
    if (ok < 0) {
        fprintf(stderr, "devaudio: cannot set period size: %s\n",
                snd_strerror(ok));
        free(params);
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
        return -1;
    }

    err = snd_pcm_hw_params(g_pcm_handle, params);
    if (err < 0) {
        fprintf(stderr, "devaudio: cannot set params: %s\n",
                snd_strerror(err));
        free(params);
        snd_pcm_close(g_pcm_handle);
        g_pcm_handle = NULL;
        return -1;
    }

    free(params);
    g_audio_state.alsa_handle = g_pcm_handle;
    g_audio_state.channels = channels;
    g_audio_state.buffer_len = 0;
    g_audio_initialized = 1;

    return 0;

#elif defined(USE_PLAN9_AUDIO)
    /* Plan 9 audio initialization */
    (void)channels;  /* Plan 9 /dev/audio handles format */

    if (g_plan9_audio_fd >= 0) {
        close(g_plan9_audio_fd);
    }

    g_plan9_audio_fd = open("/dev/audio", O_WRONLY);
    if (g_plan9_audio_fd < 0) {
        fprintf(stderr, "devaudio: cannot open /dev/audio: %s\n",
                strerror(errno));
        return -1;
    }

    g_audio_state.channels = channels;
    g_audio_state.buffer_len = 0;
    g_audio_initialized = 1;

    fprintf(stderr, "devaudio: opened Plan 9 /dev/audio\n");
    return 0;

#else
    (void)channels;
    fprintf(stderr, "devaudio: audio support not enabled - audio disabled\n");
    return -1;
#endif
}

/*
 * Write to /dev/audio
 * 9front compatible: accepts 16-bit little-endian PCM
 * Default format: stereo, 44100 Hz
 */
ssize_t devaudio_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    SoundState *state = &g_audio_state;

    (void)offset;  /* Streaming, ignore offset */

    if (state == NULL) {
        state = &g_audio_state;
    }

    /* Auto-initialize on first write (9front behavior) */
    if (!g_audio_initialized) {
        if (init_audio(state->channels) < 0) {
            return count;  /* Drop data when audio not available */
        }
    }

#ifdef USE_ALSA
    if (g_pcm_handle == NULL) {
        if (init_audio(state->channels) < 0) {
            return count;  /* Drop data when audio not available */
        }
    }

    {
        snd_pcm_sframes_t frames;
        int frame_count;
        ssize_t total_written = 0;
        short *volume_buf;

        /* Calculate frame count (16-bit samples * channels) */
        frame_count = count / (state->channels * sizeof(short));

        /* Apply volume (allocate temp buffer) */
        volume_buf = (short *)malloc(count);
        if (volume_buf == NULL) {
            fprintf(stderr, "devaudio: cannot allocate volume buffer\n");
            return -1;
        }

        memcpy(volume_buf, buf, count);
        apply_volume(volume_buf, frame_count, state->channels);

        while (total_written < (ssize_t)count) {
            frames = snd_pcm_writei(g_pcm_handle,
                                     (char *)volume_buf + total_written,
                                     frame_count);
            if (frames < 0) {
                if (frames == -EPIPE) {
                    /* Buffer underrun - recover */
                    snd_pcm_prepare(g_pcm_handle);
                    frames = snd_pcm_writei(g_pcm_handle,
                                             (char *)volume_buf + total_written,
                                             frame_count);
                    if (frames < 0) {
                        fprintf(stderr, "devaudio: cannot write: %s\n",
                                (char *)snd_strerror(frames));
                        free(volume_buf);
                        return -1;
                    }
                } else {
                    fprintf(stderr, "devaudio: write error: %s\n",
                            (char *)snd_strerror(frames));
                    free(volume_buf);
                    return -1;
                }
            }

            total_written += frames * state->channels * sizeof(short);
            frame_count -= (int)frames;
        }

        free(volume_buf);
        return total_written;
    }

#elif defined(USE_PLAN9_AUDIO)
    if (g_plan9_audio_fd < 0) {
        if (init_audio(state->channels) < 0) {
            return count;  /* Drop data when audio not available */
        }
    }

    {
        ssize_t written;
        int frame_count;
        short *volume_buf;

        /* Calculate frame count (16-bit samples * channels) */
        frame_count = count / (state->channels * sizeof(short));

        /* Apply volume (allocate temp buffer) */
        volume_buf = (short *)malloc(count);
        if (volume_buf == NULL) {
            fprintf(stderr, "devaudio: cannot allocate volume buffer\n");
            return -1;
        }

        memcpy(volume_buf, buf, count);
        apply_volume(volume_buf, frame_count, state->channels);

        written = write(g_plan9_audio_fd, volume_buf, count);
        free(volume_buf);

        if (written < 0) {
            fprintf(stderr, "devaudio: write error: %s\n", strerror(errno));
            return -1;
        }

        return written;
    }

#else
    /* No audio support - just return count as if written */
    (void)buf;
    return count;
#endif
}

/*
 * Read from /dev/audio
 * Returns audio device info (9front compatible)
 */
ssize_t devaudio_read(char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    SoundState *state = &g_audio_state;
    char info[256];
    size_t len;

    if (state == NULL) {
        state = &g_audio_state;
    }

    if (offset > 0) {
        return 0;  /* EOF after first read */
    }

    len = snprint(info, sizeof(info),
                  "audio\n"
                  "channels %d\n"
                  "rate %d\n"
                  "bits 16\n"
                  "enc little-endian\n"
                  "volume %d %d\n",
                  state->channels,
                  SOUND_SAMPLE_RATE,
                  g_volume_left,
                  g_volume_right);

    if (len > count) {
        len = count;
    }

    memcpy(buf, info, len);
    return len;
}

/*
 * Write to /dev/audioctl
 * 9front compatible control interface
 */
ssize_t devaudioctl_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    char cmd[128];
    char *p;
    size_t cmd_len;
    int left, right;

    (void)offset;

    if (count >= sizeof(cmd)) {
        cmd_len = sizeof(cmd) - 1;
    } else {
        cmd_len = count;
    }

    memcpy(cmd, buf, cmd_len);
    cmd[cmd_len] = '\0';

    /* Parse volume command: "volume left right" or "volume N" */
    if (strncmp(cmd, "volume", 6) == 0) {
        p = cmd + 6;
        while (*p == ' ' || *p == '\t') p++;

        if (sscanf(p, "%d %d", &left, &right) == 2) {
            g_volume_left = (left > 100) ? 100 : ((left < 0) ? 0 : left);
            g_volume_right = (right > 100) ? 100 : ((right < 0) ? 0 : right);
            fprintf(stderr, "devaudioctl: volume %d %d\n",
                    g_volume_left, g_volume_right);
        } else if (sscanf(p, "%d", &left) == 1) {
            g_volume_left = (left > 100) ? 100 : ((left < 0) ? 0 : left);
            g_volume_right = g_volume_left;
            fprintf(stderr, "devaudioctl: volume %d\n", g_volume_left);
        }
    }

    return count;
}

/*
 * Read from /dev/audioctl
 * Returns current audio settings (9front format)
 */
ssize_t devaudioctl_read(char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    char status[256];
    size_t len;

    (void)offset;

    len = snprint(status, sizeof(status),
                  "audio status\n"
                  "channels %d\n"
                  "rate %d\n"
                  "bits 16\n"
                  "enc little-endian\n"
                  "volume %d %d\n"
                  "status %s\n",
                  g_audio_state.channels,
                  SOUND_SAMPLE_RATE,
                  g_volume_left,
                  g_volume_right,
                  g_audio_initialized ? "on" : "off");

    if (len > count) {
        len = count;
    }

    memcpy(buf, status, len);
    return len;
}

/*
 * Volume control helpers
 */
int devaudio_set_volume(int left, int right)
{
    if (left < 0 || left > 100 || right < 0 || right > 100) {
        return -1;
    }
    g_volume_left = left;
    g_volume_right = right;
    return 0;
}

void devaudio_get_volume(int *left, int *right)
{
    if (left) *left = g_volume_left;
    if (right) *right = g_volume_right;
}

/*
 * Initialize /dev/audio device in 9P tree
 */
int devaudio_init(P9Node *dev_dir)
{
    P9Node *audio_file;
    P9Node *audioctl_file;

    /* Initialize default state */
    memset(&g_audio_state, 0, sizeof(g_audio_state));
    g_audio_state.is_playing = 1;
    g_audio_state.channels = 2;

    if (dev_dir == NULL) {
        fprintf(stderr, "devaudio_init: /dev not found\n");
        return -1;
    }

    /* Create /dev/audio file */
    audio_file = tree_create_file(dev_dir, "audio",
                                   &g_audio_state,
                                   devaudio_read,
                                   devaudio_write);
    if (audio_file == NULL) {
        fprintf(stderr, "devaudio_init: cannot create audio file\n");
        return -1;
    }

    /* Create /dev/audioctl file */
    audioctl_file = tree_create_file(dev_dir, "audioctl",
                                      &g_audio_state,
                                      devaudioctl_read,
                                      devaudioctl_write);
    if (audioctl_file == NULL) {
        fprintf(stderr, "devaudio_init: cannot create audioctl file\n");
        return -1;
    }

    fprintf(stderr, "devaudio_init: /dev/audio initialized\n");
    return 0;
}
