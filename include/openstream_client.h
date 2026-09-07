#ifndef OPENSTREAM_CLIENT_H
#define OPENSTREAM_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct OpenStreamClient OpenStreamClient;

typedef void (*openstream_on_ready)(void *context, uint16_t width,
                                    uint16_t height, uint16_t fps);
typedef void (*openstream_on_video)(void *context, const uint8_t *bytes,
                                    size_t length, bool keyframe,
                                    uint64_t presentation_time_us);
typedef void (*openstream_on_audio)(void *context, const int16_t *pcm,
                                    size_t sample_count,
                                    uint64_t presentation_time_us);
typedef void (*openstream_on_rumble)(void *context, uint32_t device_id,
                                     uint8_t strong, uint8_t weak);
typedef void (*openstream_on_error)(void *context, int32_t code);

typedef struct OpenStreamCallbacks {
    void *context;
    openstream_on_ready on_ready;
    openstream_on_video on_video;
    openstream_on_audio on_audio;
    openstream_on_rumble on_rumble;
    openstream_on_error on_error;
} OpenStreamCallbacks;

OpenStreamClient *openstream_client_start(const uint8_t *origin,
                                           size_t origin_len,
                                           const uint8_t *pairing_json,
                                           size_t pairing_len,
                                           OpenStreamCallbacks callbacks);

/*
 * Start with explicit ICE/TURN settings. `ice_urls` is a comma-separated
 * RFC 7064/7065 URL list. Credentials are optional, separate from the URL
 * list, and should come from platform secure storage. This selects full ICE
 * without relying on process environment variables.
 */
OpenStreamClient *openstream_client_start_with_ice(
    const uint8_t *origin, size_t origin_len,
    const uint8_t *pairing_json, size_t pairing_len,
    const uint8_t *ice_urls, size_t ice_urls_len,
    const uint8_t *turn_username, size_t turn_username_len,
    const uint8_t *turn_password, size_t turn_password_len,
    OpenStreamCallbacks callbacks);
int32_t openstream_client_send_input(OpenStreamClient *client,
                                     const uint8_t *payload,
                                     size_t payload_len);
/*
 * Suspend (nonzero) or resume (zero) media callbacks without tearing down
 * the session. While suspended the bridge keeps assembly ACKs flowing so the
 * host preserves the session, but drops decoded media callbacks and input.
 * Wire this to the platform background/foreground hooks. Returns 0, or -1
 * for a null handle.
 */
int32_t openstream_client_set_paused(OpenStreamClient *client, uint8_t paused);
/*
 * Report OS thermal pressure on the normalized 0-3 scale (nominal, fair,
 * serious, critical; clamped). Serious sheds half the predicted frames and
 * critical keeps keyframes only while muting PCM callbacks. Returns 0, or
 * -1 for a null handle.
 */
int32_t openstream_client_set_thermal(OpenStreamClient *client, uint8_t level);
void openstream_client_stop(OpenStreamClient *client);

#endif
