package dev.connrelay.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The phone's identity key: ECDSA P-256 in the Android Keystore, StrongBox
 * when available, otherwise the TEE. The private key cannot be exported.
 * Go passes already-hashed SHA-256 digests, hence NONEwithECDSA.
 */
class DeviceKey(private val alias: String = "connrelay-device-key-v1") : dev.connrelay.core.mobile.Signer {
    private val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    init {
        if (!ks.containsAlias(alias)) generate()
    }

    private fun spec(strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
        if (strongBox && Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(true)
        return b.build()
    }

    private fun generate() {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        try {
            kpg.initialize(spec(true))
            kpg.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            kpg.initialize(spec(false))
            kpg.generateKeyPair()
        } catch (e: Exception) {
            kpg.initialize(spec(false))
            kpg.generateKeyPair()
        }
    }

    override fun publicKeySPKI(): ByteArray = ks.getCertificate(alias).publicKey.encoded

    override fun signDER(digest: ByteArray): ByteArray {
        val s = Signature.getInstance("NONEwithECDSA")
        s.initSign(ks.getKey(alias, null) as PrivateKey)
        s.update(digest)
        return s.sign()
    }
}
