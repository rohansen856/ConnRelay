package dev.prw.prw_spike

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Device identity key in the Android Keystore (spike S6): ECDSA P-256,
 * non-exportable, StrongBox when available, otherwise TEE. Go passes an
 * already-computed SHA-256 digest, so signing uses NONEwithECDSA.
 */
class KeystoreSigner(private val alias: String = "prw-device-key") : dev.prw.spike.probe.Signer {
    private val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    var strongBox = false
        private set

    init {
        if (!ks.containsAlias(alias)) generate()
    }

    private fun spec(strong: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
        if (strong && Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(true)
        return b.build()
    }

    private fun generate() {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        try {
            kpg.initialize(spec(true))
            kpg.generateKeyPair()
            strongBox = true
        } catch (e: StrongBoxUnavailableException) {
            kpg.initialize(spec(false))
            kpg.generateKeyPair()
        } catch (e: Exception) {
            // Some devices reject DIGEST_NONE under StrongBox; fall back to TEE.
            kpg.initialize(spec(false))
            kpg.generateKeyPair()
        }
    }

    private fun privateKey(): PrivateKey = ks.getKey(alias, null) as PrivateKey

    override fun publicKeySPKI(): ByteArray = ks.getCertificate(alias).publicKey.encoded

    override fun signDER(digest: ByteArray): ByteArray {
        val s = Signature.getInstance("NONEwithECDSA")
        s.initSign(privateKey())
        s.update(digest)
        return s.sign()
    }

    /** Where the key lives and whether its material can leave the keystore. */
    fun describe(): Map<String, Any> {
        val key = privateKey()
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        val level = if (Build.VERSION.SDK_INT >= 31) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "unknown(${info.securityLevel})"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "secure_hardware" else "software"
        }
        return mapOf(
            "security_level" to level,
            "private_key_exportable" to (key.encoded != null),
            "key_size" to info.keySize,
        )
    }
}
