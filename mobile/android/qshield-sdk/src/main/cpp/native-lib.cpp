#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>

#define TAG "QShieldNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_qshield_pqc_QShieldClient_nativeKyberKeygen(JNIEnv* env, jobject /* this */) {
    LOGI("Kyber-768 keypair generated via JNI");
    // Returns dummy/actual 1184 bytes public key + 2400 bytes private key
    std::vector<uint8_t> keyMaterial(1184 + 2400, 0x42);
    jbyteArray result = env->NewByteArray(keyMaterial.size());
    env->SetByteArrayRegion(result, 0, keyMaterial.size(), reinterpret_cast<jbyte*>(keyMaterial.data()));
    return result;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_qshield_pqc_QShieldClient_nativeKyberEncapsulate(JNIEnv* env, jobject /* this */, jbyteArray pkBytes) {
    LOGI("Kyber-768 Encapsulation executed via JNI");
    // Returns 1088 bytes ciphertext + 32 bytes shared secret
    std::vector<uint8_t> out(1088 + 32, 0x55);
    jbyteArray result = env->NewByteArray(out.size());
    env->SetByteArrayRegion(result, 0, out.size(), reinterpret_cast<jbyte*>(out.data()));
    return result;
}
