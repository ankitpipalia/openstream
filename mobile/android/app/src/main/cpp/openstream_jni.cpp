#include <jni.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <new>

#include "openstream_client.h"

namespace {

struct BridgeHandle;

struct BridgeContext {
    JavaVM *vm;
    jobject callbacks;
    std::mutex lifecycle_mutex;
    size_t callbacks_in_flight = 0;
    bool cleanup_requested = false;
    bool cleanup_started = false;
    BridgeHandle *owner = nullptr;

    BridgeContext(JavaVM *vm, jobject callbacks) : vm(vm), callbacks(callbacks) {}
};

struct BridgeHandle {
    OpenStreamClient *client;
    BridgeContext *context;
};

void clear_exception(JNIEnv *env);

bool begin_callback(BridgeContext *context) {
    std::lock_guard<std::mutex> lock(context->lifecycle_mutex);
    if (context->cleanup_requested || context->cleanup_started) {
        return false;
    }
    ++context->callbacks_in_flight;
    return true;
}

void destroy_context(BridgeContext *context, JNIEnv *env) {
    if (context == nullptr || context->owner == nullptr) {
        return;
    }
    bool detach = false;
    if (env == nullptr && context->vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
        detach = true;
    }
    if (env != nullptr && context->callbacks != nullptr) {
        env->DeleteGlobalRef(context->callbacks);
        clear_exception(env);
    }
    auto *owner = context->owner;
    JavaVM *vm = context->vm;
    delete context;
    delete owner;
    if (detach) {
        vm->DetachCurrentThread();
    }
}

JNIEnv *environment(BridgeContext *context, bool *detach) {
    *detach = false;
    JNIEnv *env = nullptr;
    if (context->vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) == JNI_OK) {
        return env;
    }
    if (context->vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
        return nullptr;
    }
    *detach = true;
    return env;
}

void finish_callback(BridgeContext *context, bool detach, JNIEnv *env) {
    JavaVM *vm = context->vm;
    bool destroy = false;
    {
        std::lock_guard<std::mutex> lock(context->lifecycle_mutex);
        if (context->callbacks_in_flight > 0) {
            --context->callbacks_in_flight;
        }
        if (context->callbacks_in_flight == 0 && context->cleanup_requested &&
            !context->cleanup_started) {
            context->cleanup_started = true;
            destroy = true;
        }
    }
    if (destroy) {
        destroy_context(context, env);
    }
    if (detach && !destroy) {
        vm->DetachCurrentThread();
    }
}

void clear_exception(JNIEnv *env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

extern "C" void on_ready(void *opaque, uint16_t width, uint16_t height, uint16_t fps) {
    auto *context = static_cast<BridgeContext *>(opaque);
    if (context == nullptr || !begin_callback(context)) {
        return;
    }
    bool detach = false;
    JNIEnv *env = environment(context, &detach);
    if (env == nullptr) {
        finish_callback(context, detach, env);
        return;
    }
    jclass klass = env->GetObjectClass(context->callbacks);
    if (klass != nullptr) {
        jmethodID method = env->GetMethodID(klass, "onReady", "(III)V");
        if (method != nullptr) {
            env->CallVoidMethod(context->callbacks, method, static_cast<jint>(width),
                                static_cast<jint>(height), static_cast<jint>(fps));
        }
        env->DeleteLocalRef(klass);
    }
    clear_exception(env);
    finish_callback(context, detach, env);
}

extern "C" void on_video(void *opaque, const uint8_t *bytes, size_t length, bool keyframe,
                          uint64_t presentation_time_us) {
    auto *context = static_cast<BridgeContext *>(opaque);
    if (context == nullptr || !begin_callback(context)) {
        return;
    }
    bool detach = false;
    JNIEnv *env = environment(context, &detach);
    if (env == nullptr || (bytes == nullptr && length != 0) ||
        length > static_cast<size_t>(INT32_MAX)) {
        finish_callback(context, detach, env);
        return;
    }
    jbyteArray array = env->NewByteArray(static_cast<jsize>(length));
    if (array != nullptr) {
        env->SetByteArrayRegion(array, 0, static_cast<jsize>(length),
                                reinterpret_cast<const jbyte *>(bytes));
        jclass klass = env->GetObjectClass(context->callbacks);
        if (klass != nullptr) {
            jmethodID method = env->GetMethodID(klass, "onVideo", "([BZJ)V");
            if (method != nullptr) {
                env->CallVoidMethod(context->callbacks, method, array, keyframe,
                                    static_cast<jlong>(presentation_time_us));
            }
            env->DeleteLocalRef(klass);
        }
        clear_exception(env);
        env->DeleteLocalRef(array);
    }
    // NewByteArray/SetByteArrayRegion can raise an OOM or bounds exception.
    // Clear it even when allocation failed; otherwise the pending JNI
    // exception escapes the native callback and poisons the next bridge call.
    clear_exception(env);
    finish_callback(context, detach, env);
}

extern "C" void on_audio(void *opaque, const int16_t *pcm, size_t sample_count,
                          uint64_t presentation_time_us) {
    auto *context = static_cast<BridgeContext *>(opaque);
    if (context == nullptr || !begin_callback(context)) {
        return;
    }
    bool detach = false;
    JNIEnv *env = environment(context, &detach);
    if (env == nullptr || (pcm == nullptr && sample_count != 0) ||
        sample_count > static_cast<size_t>(INT32_MAX)) {
        finish_callback(context, detach, env);
        return;
    }
    jshortArray array = env->NewShortArray(static_cast<jsize>(sample_count));
    if (array != nullptr) {
        env->SetShortArrayRegion(array, 0, static_cast<jsize>(sample_count),
                                 reinterpret_cast<const jshort *>(pcm));
        jclass klass = env->GetObjectClass(context->callbacks);
        if (klass != nullptr) {
            jmethodID method = env->GetMethodID(klass, "onAudio", "([SJ)V");
            if (method != nullptr) {
                env->CallVoidMethod(context->callbacks, method, array,
                                    static_cast<jlong>(presentation_time_us));
            }
            env->DeleteLocalRef(klass);
        }
        clear_exception(env);
        env->DeleteLocalRef(array);
    }
    clear_exception(env);
    finish_callback(context, detach, env);
}

extern "C" void on_rumble(void *opaque, uint32_t device_id, uint8_t strong, uint8_t weak) {
    auto *context = static_cast<BridgeContext *>(opaque);
    if (context == nullptr || !begin_callback(context)) {
        return;
    }
    bool detach = false;
    JNIEnv *env = environment(context, &detach);
    if (env == nullptr) {
        finish_callback(context, detach, env);
        return;
    }
    jclass klass = env->GetObjectClass(context->callbacks);
    if (klass != nullptr) {
        jmethodID method = env->GetMethodID(klass, "onRumble", "(IBB)V");
        if (method != nullptr) {
            env->CallVoidMethod(context->callbacks, method, static_cast<jint>(device_id),
                                static_cast<jbyte>(strong), static_cast<jbyte>(weak));
        }
        env->DeleteLocalRef(klass);
    }
    clear_exception(env);
    finish_callback(context, detach, env);
}

extern "C" void on_displays(void *opaque, const uint8_t *bytes, size_t length) {
    auto *context = static_cast<BridgeContext *>(opaque);
    if (context == nullptr || !begin_callback(context)) {
        return;
    }
    bool detach = false;
    JNIEnv *env = environment(context, &detach);
    if (env == nullptr || (bytes == nullptr && length != 0) ||
        length > static_cast<size_t>(INT32_MAX)) {
        finish_callback(context, detach, env);
        return;
    }
    jbyteArray array = env->NewByteArray(static_cast<jsize>(length));
    if (array != nullptr) {
        env->SetByteArrayRegion(array, 0, static_cast<jsize>(length),
                                reinterpret_cast<const jbyte *>(bytes));
        jclass klass = env->GetObjectClass(context->callbacks);
        if (klass != nullptr) {
            jmethodID method = env->GetMethodID(klass, "onDisplays", "([B)V");
            if (method != nullptr) {
                env->CallVoidMethod(context->callbacks, method, array);
            }
            env->DeleteLocalRef(klass);
        }
        env->DeleteLocalRef(array);
    }
    clear_exception(env);
    finish_callback(context, detach, env);
}

extern "C" void on_error(void *opaque, int32_t code) {
    auto *context = static_cast<BridgeContext *>(opaque);
    if (context == nullptr || !begin_callback(context)) {
        return;
    }
    bool detach = false;
    JNIEnv *env = environment(context, &detach);
    if (env == nullptr) {
        finish_callback(context, detach, env);
        return;
    }
    jclass klass = env->GetObjectClass(context->callbacks);
    if (klass != nullptr) {
        jmethodID method = env->GetMethodID(klass, "onError", "(I)V");
        if (method != nullptr) {
            env->CallVoidMethod(context->callbacks, method, static_cast<jint>(code));
        }
        env->DeleteLocalRef(klass);
    }
    clear_exception(env);
    finish_callback(context, detach, env);
}

jlong start_client(JNIEnv *env, jstring origin, jstring pairing_json, jstring ice_urls,
                   jstring turn_username, jstring turn_password, jobject callbacks) {
    if (origin == nullptr || pairing_json == nullptr || callbacks == nullptr) {
        return 0;
    }
    const char *origin_chars = env->GetStringUTFChars(origin, nullptr);
    const char *pairing_chars = env->GetStringUTFChars(pairing_json, nullptr);
    const char *ice_chars =
        ice_urls == nullptr ? nullptr : env->GetStringUTFChars(ice_urls, nullptr);
    const char *username_chars =
        turn_username == nullptr ? nullptr : env->GetStringUTFChars(turn_username, nullptr);
    const char *password_chars =
        turn_password == nullptr ? nullptr : env->GetStringUTFChars(turn_password, nullptr);
    if (origin_chars == nullptr || pairing_chars == nullptr ||
        (ice_urls != nullptr && ice_chars == nullptr) ||
        (turn_username != nullptr && username_chars == nullptr) ||
        (turn_password != nullptr && password_chars == nullptr)) {
        if (origin_chars != nullptr) env->ReleaseStringUTFChars(origin, origin_chars);
        if (pairing_chars != nullptr) env->ReleaseStringUTFChars(pairing_json, pairing_chars);
        if (ice_chars != nullptr) env->ReleaseStringUTFChars(ice_urls, ice_chars);
        if (username_chars != nullptr) env->ReleaseStringUTFChars(turn_username, username_chars);
        if (password_chars != nullptr) env->ReleaseStringUTFChars(turn_password, password_chars);
        return 0;
    }

    JavaVM *vm = nullptr;
    if (env->GetJavaVM(&vm) != JNI_OK) {
        env->ReleaseStringUTFChars(origin, origin_chars);
        env->ReleaseStringUTFChars(pairing_json, pairing_chars);
        if (ice_chars != nullptr) env->ReleaseStringUTFChars(ice_urls, ice_chars);
        if (username_chars != nullptr) env->ReleaseStringUTFChars(turn_username, username_chars);
        if (password_chars != nullptr) env->ReleaseStringUTFChars(turn_password, password_chars);
        return 0;
    }

    auto global_callbacks = env->NewGlobalRef(callbacks);
    if (global_callbacks == nullptr) {
        env->ReleaseStringUTFChars(origin, origin_chars);
        env->ReleaseStringUTFChars(pairing_json, pairing_chars);
        if (ice_chars != nullptr) env->ReleaseStringUTFChars(ice_urls, ice_chars);
        if (username_chars != nullptr) env->ReleaseStringUTFChars(turn_username, username_chars);
        if (password_chars != nullptr) env->ReleaseStringUTFChars(turn_password, password_chars);
        return 0;
    }
    auto context = std::make_unique<BridgeContext>(vm, global_callbacks);
    OpenStreamCallbacks table{};
    table.context = context.get();
    table.on_ready = on_ready;
    table.on_video = on_video;
    table.on_audio = on_audio;
    table.on_rumble = on_rumble;
    table.on_displays = on_displays;
    table.on_error = on_error;

    OpenStreamClient *client = nullptr;
    if (ice_urls == nullptr) {
        client = openstream_client_start(
            reinterpret_cast<const uint8_t *>(origin_chars),
            static_cast<size_t>(env->GetStringUTFLength(origin)),
            reinterpret_cast<const uint8_t *>(pairing_chars),
            static_cast<size_t>(env->GetStringUTFLength(pairing_json)), table);
    } else {
        client = openstream_client_start_with_ice(
            reinterpret_cast<const uint8_t *>(origin_chars),
            static_cast<size_t>(env->GetStringUTFLength(origin)),
            reinterpret_cast<const uint8_t *>(pairing_chars),
            static_cast<size_t>(env->GetStringUTFLength(pairing_json)),
            reinterpret_cast<const uint8_t *>(ice_chars),
            static_cast<size_t>(env->GetStringUTFLength(ice_urls)),
            reinterpret_cast<const uint8_t *>(username_chars),
            turn_username == nullptr
                ? 0
                : static_cast<size_t>(env->GetStringUTFLength(turn_username)),
            reinterpret_cast<const uint8_t *>(password_chars),
            turn_password == nullptr
                ? 0
                : static_cast<size_t>(env->GetStringUTFLength(turn_password)),
            table);
    }
    env->ReleaseStringUTFChars(origin, origin_chars);
    env->ReleaseStringUTFChars(pairing_json, pairing_chars);
    if (ice_chars != nullptr) env->ReleaseStringUTFChars(ice_urls, ice_chars);
    if (username_chars != nullptr) env->ReleaseStringUTFChars(turn_username, username_chars);
    if (password_chars != nullptr) env->ReleaseStringUTFChars(turn_password, password_chars);
    if (client == nullptr) {
        env->DeleteGlobalRef(global_callbacks);
        return 0;
    }
    auto *handle = new (std::nothrow) BridgeHandle{client, context.get()};
    if (handle == nullptr) {
        openstream_client_stop(client);
        env->DeleteGlobalRef(global_callbacks);
        return 0;
    }
    context.release();
    handle->context->owner = handle;
    return reinterpret_cast<jlong>(handle);
}

}  // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_app_openstream_OpenStreamNative_nativeStart(JNIEnv *env, jclass, jstring origin,
                                                 jstring pairing_json, jobject callbacks) {
    return start_client(env, origin, pairing_json, nullptr, nullptr, nullptr, callbacks);
}

extern "C" JNIEXPORT jlong JNICALL
Java_app_openstream_OpenStreamNative_nativeStartWithIce(JNIEnv *env, jclass, jstring origin,
                                                        jstring pairing_json, jstring ice_urls,
                                                        jstring turn_username,
                                                        jstring turn_password,
                                                        jobject callbacks) {
    if (ice_urls == nullptr) {
        return 0;
    }
    return start_client(env, origin, pairing_json, ice_urls, turn_username, turn_password,
                        callbacks);
}

extern "C" JNIEXPORT jint JNICALL
Java_app_openstream_OpenStreamNative_nativeSendInput(JNIEnv *env, jclass, jlong value,
                                                     jbyteArray payload) {
    auto *handle = reinterpret_cast<BridgeHandle *>(value);
    if (handle == nullptr || payload == nullptr) {
        return -1;
    }
    jsize length = env->GetArrayLength(payload);
    if (env->ExceptionCheck()) {
        clear_exception(env);
        return -1;
    }
    jbyte *bytes = env->GetByteArrayElements(payload, nullptr);
    if (bytes == nullptr) {
        clear_exception(env);
        return -1;
    }
    int32_t result = openstream_client_send_input(
        handle->client, reinterpret_cast<const uint8_t *>(bytes), static_cast<size_t>(length));
    env->ReleaseByteArrayElements(payload, bytes, JNI_ABORT);
    clear_exception(env);
    return static_cast<jint>(result);
}

extern "C" JNIEXPORT jint JNICALL
Java_app_openstream_OpenStreamNative_nativeSelectDisplay(JNIEnv *, jclass, jlong value,
                                                          jint display_id) {
    auto *handle = reinterpret_cast<BridgeHandle *>(value);
    if (handle == nullptr || display_id < 0) {
        return -1;
    }
    return static_cast<jint>(openstream_client_select_display(
        handle->client, static_cast<uint32_t>(display_id)));
}

extern "C" JNIEXPORT jint JNICALL
Java_app_openstream_OpenStreamNative_nativeSetPaused(JNIEnv *, jclass, jlong value,
                                                     jboolean paused) {
    auto *handle = reinterpret_cast<BridgeHandle *>(value);
    if (handle == nullptr) {
        return -1;
    }
    return static_cast<jint>(
        openstream_client_set_paused(handle->client, paused == JNI_TRUE ? 1 : 0));
}

extern "C" JNIEXPORT jint JNICALL
Java_app_openstream_OpenStreamNative_nativeSetThermal(JNIEnv *, jclass, jlong value,
                                                      jint level) {
    auto *handle = reinterpret_cast<BridgeHandle *>(value);
    if (handle == nullptr) {
        return -1;
    }
    if (level < 0) {
        level = 0;
    }
    if (level > 3) {
        level = 3;
    }
    return static_cast<jint>(
        openstream_client_set_thermal(handle->client, static_cast<uint8_t>(level)));
}

extern "C" JNIEXPORT void JNICALL
Java_app_openstream_OpenStreamNative_nativeStop(JNIEnv *, jclass, jlong value) {
    auto *handle = reinterpret_cast<BridgeHandle *>(value);
    if (handle == nullptr) {
        return;
    }
    openstream_client_stop(handle->client);
    bool destroy = false;
    {
        std::lock_guard<std::mutex> lock(handle->context->lifecycle_mutex);
        handle->context->cleanup_requested = true;
        if (handle->context->callbacks_in_flight == 0 &&
            !handle->context->cleanup_started) {
            handle->context->cleanup_started = true;
            destroy = true;
        }
    }
    if (destroy) {
        destroy_context(handle->context, nullptr);
    }
}
