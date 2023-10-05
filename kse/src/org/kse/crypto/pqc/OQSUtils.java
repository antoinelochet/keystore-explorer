package org.kse.crypto.pqc;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.ResourceBundle;

import com.nimbusds.jose.jwk.Curve;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

public final class OQSUtils {

    private static final ResourceBundle PUBLIC_KEY_RESOURCE_BUNDLE = ResourceBundle.getBundle("org/kse/crypto/publickey/resources");
    private static final ResourceBundle PRIVATE_KEY_RESOURCE_BUNDLE = ResourceBundle.getBundle("org/kse/crypto/privatekey/resources");

    private static final byte[] OQS_HEADER = new byte[]{0x00, 0x00, 0x00};
    private static final Map<String, Curve> CURVE_BY_OID = new HashMap<>();
    private static final Map<String, DilithiumParameters> DILITHIUM_PARAMETERS_MAP_BY_OID = new HashMap<>();
    private static final Map<String, DilithiumPrivateKeyParametersLengths> DILITHIUM_PRIVATE_KEY_PARAMETERS_MAP_BY_OID = new HashMap<>();
    private final static int DILITHIUM_SEED_BYTES = 32;
    private final static int DILITHIUM_POLY_T1_PACKED_BYTES = 320;
    private final static int DILITHIUM_POLY_T0_PACKED_BYTES = 416;

    public static final Map<String, KeyPairType> KEYPAIR_TYPE_BY_OID = new HashMap<>();
    public static final Map<String, KeyPairType> KEYPAIR_TYPE_BY_NAME = new HashMap<>();

    static {
        KEYPAIR_TYPE_BY_OID.put(KeyPairType.P256_DILITHIUM2.oid(), KeyPairType.P256_DILITHIUM2);
        KEYPAIR_TYPE_BY_OID.put(KeyPairType.RSA3072_DILITHIUM2.oid(), KeyPairType.RSA3072_DILITHIUM2);
        KEYPAIR_TYPE_BY_OID.put(KeyPairType.P384_DILITHIUM3.oid(), KeyPairType.P384_DILITHIUM3);
        KEYPAIR_TYPE_BY_OID.put(KeyPairType.P521_DILITHIUM5.oid(), KeyPairType.P521_DILITHIUM5);

        KEYPAIR_TYPE_BY_NAME.put(KeyPairType.P256_DILITHIUM2.name().toLowerCase(Locale.ROOT), KeyPairType.P256_DILITHIUM2);
        KEYPAIR_TYPE_BY_NAME.put(KeyPairType.RSA3072_DILITHIUM2.name().toLowerCase(Locale.ROOT), KeyPairType.RSA3072_DILITHIUM2);
        KEYPAIR_TYPE_BY_NAME.put(KeyPairType.P384_DILITHIUM3.name().toLowerCase(Locale.ROOT), KeyPairType.P384_DILITHIUM3);
        KEYPAIR_TYPE_BY_NAME.put(KeyPairType.P521_DILITHIUM5.name().toLowerCase(Locale.ROOT), KeyPairType.P521_DILITHIUM5);

        CURVE_BY_OID.put(KeyPairType.P256_DILITHIUM2.oid(), Curve.P_256);
        CURVE_BY_OID.put(KeyPairType.P384_DILITHIUM3.oid(), Curve.P_384);
        CURVE_BY_OID.put(KeyPairType.P521_DILITHIUM5.oid(), Curve.P_521);

        DILITHIUM_PARAMETERS_MAP_BY_OID.put(KeyPairType.P256_DILITHIUM2.oid(), DilithiumParameters.dilithium2);
        DILITHIUM_PARAMETERS_MAP_BY_OID.put(KeyPairType.P384_DILITHIUM3.oid(), DilithiumParameters.dilithium3);
        DILITHIUM_PARAMETERS_MAP_BY_OID.put(KeyPairType.P521_DILITHIUM5.oid(), DilithiumParameters.dilithium5);

        DILITHIUM_PRIVATE_KEY_PARAMETERS_MAP_BY_OID.put(KeyPairType.P256_DILITHIUM2.oid(), DilithiumPrivateKeyParametersLengths.DILITHIUM2);
        DILITHIUM_PRIVATE_KEY_PARAMETERS_MAP_BY_OID.put(KeyPairType.P384_DILITHIUM3.oid(), DilithiumPrivateKeyParametersLengths.DILITHIUM3);
        DILITHIUM_PRIVATE_KEY_PARAMETERS_MAP_BY_OID.put(KeyPairType.P521_DILITHIUM5.oid(), DilithiumPrivateKeyParametersLengths.DILITHIUM5);
    }

    private OQSUtils() {
    }

    public static PublicKey getOQSPublicKeyFromPEM(byte[] certData) {
        try {
            // Check if stream is PEM encoded
            PemInfo pemInfo = PemUtil.decode(certData);

            if (pemInfo != null) {
                // It is - get DER from PEM
                certData = pemInfo.getContent();
            }

            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certData);
            SubjectPublicKeyInfo subjectPublicKeyInfo = x509CertificateHolder.getSubjectPublicKeyInfo();
            DERSequence asn1Primitive = (DERSequence) subjectPublicKeyInfo.toASN1Primitive();
            return getOqsPublicKey(asn1Primitive);
        } catch (Exception ex) {
            throw new IllegalArgumentException(PUBLIC_KEY_RESOURCE_BUNDLE.getString("NoLoadOpenSslOQSPublicKey.exception.message"), ex);
        }
    }

    public static PublicKey getOQSPublicKeyFromPublicKey(byte[] pkData) {
        try {
            // Check if stream is PEM encoded
            PemInfo pemInfo = PemUtil.decode(pkData);

            if (pemInfo != null) {
                // It is - get DER from PEM
                pkData = pemInfo.getContent();
            }

            DLSequence asn1Primitive = (DLSequence) DLSequence.getInstance(pkData);
            return getPublicKey(asn1Primitive);
        } catch (Exception ex) {
            throw new IllegalArgumentException(PUBLIC_KEY_RESOURCE_BUNDLE.getString("NoLoadOpenSslOQSPublicKey.exception.message"), ex);
        }
    }

    public static PrivateKey getOQSPrivateKeyFromPEM(byte[] pkData) {
        try {
            // Check if stream is PEM encoded
            PemInfo pemInfo = PemUtil.decode(pkData);

            if (pemInfo != null) {
                // It is - get DER from PEM
                pkData = pemInfo.getContent();
            }

            return new OQSPrivateKey(pkData);
        } catch (Exception ex) {
            throw new IllegalArgumentException(PRIVATE_KEY_RESOURCE_BUNDLE.getString("NoLoadOpenSslOQSPrivateKey.exception.message"), ex);
        }
    }


    public static OQSPublicKey oqsPublicKeysFromX509PublicKey(PublicKey publicKey) throws CryptoException {
        if (publicKey instanceof OQSPublicKey) {
            return (OQSPublicKey) publicKey;
        }
        byte[] encoded = publicKey.getEncoded();
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(encoded);
        return getPublicKey(asn1Sequence);
    }

    public static OQSPublicKey getPublicKey(ASN1Sequence asn1Sequence) {
        DLSequence algIDSequence = (DLSequence) asn1Sequence.getObjectAt(0);
        ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) algIDSequence.getObjectAt(0);
        String algorithm = objectIdentifier.getId();
        DERBitString derBitString = (DERBitString) asn1Sequence.getObjectAt(1);
        byte[] octets = derBitString.getOctets();
        return new OQSPublicKey(algorithm, octets);
    }

    private static OQSPublicKey getOqsPublicKey(ASN1Sequence asn1Sequence) {
        AlgorithmIdentifier objectIdentifier = (AlgorithmIdentifier) asn1Sequence.getObjectAt(0);
        String algorithm = objectIdentifier.getAlgorithm().getId();
        DERBitString derBitString = (DERBitString) asn1Sequence.getObjectAt(1);
        byte[] octets = derBitString.getOctets();
        return new OQSPublicKey(algorithm, octets);
    }

    private static OQSPublicKey getOqsPublicKey(DLSequence dlSequence) {
        return getPublicKey(dlSequence);
    }

    private static ECPublicKey getEcPublicKey(byte[] classic, String algorithm) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", KSE.BC);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(CURVE_BY_OID.get(algorithm).getStdName());
        parameters.init(ecGenParameterSpec);
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        ECPoint ecPoint = ECPointUtil.decodePoint(ecParameters.getCurve(), classic);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameters);
        return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
    }

    public static class OQSPublicKey implements PublicKey {
        private final PublicKey classicPublicKey;
        private final PublicKey pqcPublicKey;
        private final String algorithm;
        private final String format;
        private final byte[] encoded;

        public OQSPublicKey(String algorithm, byte[] encoded) {
            this.format = "OQS";
            this.algorithm = KEYPAIR_TYPE_BY_OID.get(algorithm).name().toLowerCase(Locale.ROOT);
            this.encoded = encoded;
            try {
                checkOQSHeader(encoded);
                byte[] withoutHeader = ArrayUtils.subarray(encoded, 3, encoded.length);
                int classicLength = (withoutHeader[0] & 0xff);
                byte[] classic = new byte[classicLength];
                System.arraycopy(withoutHeader, 1, classic, 0, classicLength);

                ECPublicKey ecPublicKey = getEcPublicKey(classic, algorithm);
                byte[] dilithiumEncodedKey = ArrayUtils.subarray(withoutHeader, classicLength + 1, encoded.length + 1);
                // rho is always 32 bytes long so t1 is the left-over
                DilithiumPublicKeyParameters dilithiumPublicKeyParameters = new DilithiumPublicKeyParameters(DILITHIUM_PARAMETERS_MAP_BY_OID.get(algorithm), dilithiumEncodedKey);
                this.classicPublicKey = ecPublicKey;
                this.pqcPublicKey = new BCDilithiumPublicKey(dilithiumPublicKeyParameters);
            } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException e) {
                throw new IllegalArgumentException();
            }
        }

        public PublicKey getClassicPublicKey() {
            return classicPublicKey;
        }

        public PublicKey getPqcPublicKey() {
            return pqcPublicKey;
        }

        @Override
        public String getAlgorithm() {
            return this.algorithm;
        }

        @Override
        public String getFormat() {
            return this.format;
        }

        @Override
        public byte[] getEncoded() {
            return this.encoded;
        }
    }

    private static DilithiumPrivateKeyParameters rebuildDilithiumPrivateKey(byte[] oqsEncodedPrivateKey, String algorithm) {
        checkOQSHeader(oqsEncodedPrivateKey);

        byte[] withoutHeader = ArrayUtils.subarray(oqsEncodedPrivateKey, 3, oqsEncodedPrivateKey.length);
        int classicLength = (withoutHeader[0] & 0xff);
        byte[] dilithiumEncodedKey = ArrayUtils.subarray(withoutHeader, classicLength + 1, withoutHeader.length + 1);
        DilithiumPrivateKeyParametersLengths dilithiumPrivateKeyParametersLengths = DILITHIUM_PRIVATE_KEY_PARAMETERS_MAP_BY_OID.get(algorithm);
        // rho is always 32 bytes long
        // K is always 32 bytes long
        // tr is always 32 bytes long
        // s1 is l * polyEtaPackedBytes
        // s2 is k * polyEtaPackedBytes
        // t0 is k * 416 bytes
        // t1 is k * 320 bytes
        // encoded is rho + K + tr + s1 + s2 + t0 + rho + t1
        byte[] rho = new byte[DILITHIUM_SEED_BYTES];
        byte[] K = new byte[DILITHIUM_SEED_BYTES];
        byte[] tr = new byte[DILITHIUM_SEED_BYTES];
        byte[] s1 = new byte[dilithiumPrivateKeyParametersLengths.lLength * dilithiumPrivateKeyParametersLengths.polyEtaPackedBytes];
        byte[] s2 = new byte[dilithiumPrivateKeyParametersLengths.kLength * dilithiumPrivateKeyParametersLengths.polyEtaPackedBytes];
        byte[] t0 = new byte[dilithiumPrivateKeyParametersLengths.kLength * DILITHIUM_POLY_T0_PACKED_BYTES];
        byte[] t1 = new byte[dilithiumPrivateKeyParametersLengths.kLength * DILITHIUM_POLY_T1_PACKED_BYTES];
        System.arraycopy(dilithiumEncodedKey, 0, rho, 0, rho.length);
        System.arraycopy(dilithiumEncodedKey, rho.length, K, 0, K.length);
        System.arraycopy(dilithiumEncodedKey, rho.length + K.length, tr, 0, tr.length);
        System.arraycopy(dilithiumEncodedKey, rho.length + K.length + tr.length, s1, 0, s1.length);
        System.arraycopy(dilithiumEncodedKey, rho.length + K.length + tr.length + s1.length, s2, 0, s2.length);
        System.arraycopy(dilithiumEncodedKey, rho.length + K.length + tr.length + s1.length + s2.length, t0, 0, t0.length);
        System.arraycopy(dilithiumEncodedKey, rho.length + K.length + tr.length + s1.length + s2.length + t0.length + rho.length, t1, 0, t1.length);
        return new DilithiumPrivateKeyParameters(DILITHIUM_PARAMETERS_MAP_BY_OID.get(algorithm), rho, K, tr, s1, s2, t0, t1);
    }

    public static class OQSPrivateKey implements PrivateKey {

        private final PrivateKey classicPrivateKey;
        private final PrivateKey pqcPrivateKey;
        private final String algorithm;
        private final String format;
        private final byte[] encoded;

        public OQSPrivateKey(byte[] encoded) {
            this.format = "PKCS#8+OQS";
            this.encoded = encoded;
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(encoded)) {
                // Read OpenSSL DER structure
                ASN1Primitive openSsl = asn1InputStream.readObject();
                asn1InputStream.close();

                if (openSsl instanceof ASN1Sequence) {
                    ASN1Sequence seq = (ASN1Sequence) openSsl;
                    DLSequence algIDSequence = (DLSequence) seq.getObjectAt(1);
                    ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) algIDSequence.getObjectAt(0);
                    String algorithm = objectIdentifier.getId();
                    this.algorithm = KEYPAIR_TYPE_BY_OID.get(algorithm).name().toLowerCase(Locale.ROOT);
                    DEROctetString derOctetString = (DEROctetString) seq.getObjectAt(2);
                    byte[] oqsEncodedPrivateKey = ((DEROctetString) DEROctetString.fromByteArray(derOctetString.getOctets())).getOctets();

                    DilithiumPrivateKeyParameters dilithiumPrivateKeyParameters = rebuildDilithiumPrivateKey(oqsEncodedPrivateKey, algorithm);
                    this.pqcPrivateKey = new BCDilithiumPrivateKey(dilithiumPrivateKeyParameters);
                    this.classicPrivateKey = rebuildECPrivateKey(oqsEncodedPrivateKey, seq, algorithm);
                } else {
                    throw new IllegalArgumentException(PRIVATE_KEY_RESOURCE_BUNDLE.getString("NoLoadOpenSslOQSPrivateKey.exception.message"));
                }
            } catch (Exception ex) {
                throw new IllegalArgumentException(PRIVATE_KEY_RESOURCE_BUNDLE.getString("NoLoadOpenSslOQSPrivateKey.exception.message"), ex);
            }
        }

        public PrivateKey getClassicPrivateKey() {
            return classicPrivateKey;
        }

        public PrivateKey getPqcPrivateKey() {
            return pqcPrivateKey;
        }

        @Override
        public String getAlgorithm() {
            return this.algorithm;
        }

        @Override
        public String getFormat() {
            return this.format;
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }
    }

    private static void checkOQSHeader(byte[] oqsEncodedPrivateKey) {
        byte[] header = new byte[3];
        System.arraycopy(oqsEncodedPrivateKey, 0, header, 0, 3);
        if (!Objects.deepEquals(header, OQS_HEADER)) {
            throw new IllegalArgumentException("Not a OQS encoded key");
        }
    }

    private static PrivateKey rebuildECPrivateKey(byte[] oqsEncodedPrivateKey, ASN1Sequence seq, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] withoutHeaderAndLength = ArrayUtils.subarray(oqsEncodedPrivateKey, 4, oqsEncodedPrivateKey.length);
        int ecLength = (withoutHeaderAndLength[2] & 0xff);
        byte[] classic = new byte[ecLength + 3];
        System.arraycopy(withoutHeaderAndLength, 0, classic, 0, classic.length);
        ASN1Sequence derSequence = ASN1Sequence.getInstance(classic);
        ASN1EncodableVector capsuleVector = new ASN1EncodableVector();
        capsuleVector.add(seq.getObjectAt(0));
        Curve curve = CURVE_BY_OID.get(algorithm);
        capsuleVector.add(new DLSequence(new ASN1Encodable[]{
                X9ObjectIdentifiers.id_ecPublicKey,
                new ASN1ObjectIdentifier(curve.getOID())
        }));
        capsuleVector.add(new DEROctetString(derSequence.getEncoded()));
        DLSequence capsuleSequence = new DLSequence(capsuleVector);
        byte[] encodedCapsule = capsuleSequence.getEncoded();
        KeyFactory keyFactory = KeyFactory.getInstance("EC", KSE.BC);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedCapsule);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    private static class DilithiumPrivateKeyParametersLengths {

        private static final DilithiumPrivateKeyParametersLengths DILITHIUM2 = new DilithiumPrivateKeyParametersLengths(4, 4, 96);
        private static final DilithiumPrivateKeyParametersLengths DILITHIUM3 = new DilithiumPrivateKeyParametersLengths(6, 5, 128);
        private static final DilithiumPrivateKeyParametersLengths DILITHIUM5 = new DilithiumPrivateKeyParametersLengths(8, 7, 96);

        private final int kLength;
        private final int lLength;
        private final int polyEtaPackedBytes;

        private DilithiumPrivateKeyParametersLengths(int kLength, int lLength, int polyEtaPackedBytes) {
            this.kLength = kLength;
            this.lLength = lLength;
            this.polyEtaPackedBytes = polyEtaPackedBytes;
        }
    }
}
