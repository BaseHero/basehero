#include <jni.h>

// The debug-only target APK loads this library before invoking the bridge.
// CheckJNI validates the actual native callback signature and byte[] transport.
JNIEXPORT void JNICALL
Java_app_basehero_devicekeys_DeviceKeysBridge_nativeComplete(JNIEnv *env, jclass cls,
                                                               jlong ticket, jint code,
                                                               jbyteArray bytes) {
    (void)cls;
    jclass sink = (*env)->FindClass(env, "app/basehero/devicekeys/ProbeResults");
    if (sink == NULL) return;
    jmethodID complete = (*env)->GetStaticMethodID(env, sink, "complete", "(JI[B)V");
    if (complete != NULL) (*env)->CallStaticVoidMethod(env, sink, complete, ticket, code, bytes);
    (*env)->DeleteLocalRef(env, sink);
}
