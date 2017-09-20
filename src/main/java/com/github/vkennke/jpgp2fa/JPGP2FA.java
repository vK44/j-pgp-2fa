package com.github.vkennke.jpgp2fa;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import static java.lang.System.lineSeparator;
import static java.util.UUID.randomUUID;
import static java.util.stream.Collectors.toList;
import static java.util.stream.StreamSupport.stream;
import static org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.CAST5;
import static org.bouncycastle.openpgp.PGPLiteralData.UTF8;
import static org.bouncycastle.openpgp.PGPUtil.getDecoderStream;
import static org.bouncycastle.openpgp.PGPUtil.writeFileToLiteralData;

public final class JPGP2FA {

    public static String encrypt(byte[] publicKey, String secret) {
        try (InputStream inputStream = new ByteArrayInputStream(publicKey)) {
            return encrypt(inputStream, secret);
        } catch (IOException e) {
            throw new JPGP2FAException(e);
        }
    }

    public static String encrypt(InputStream publicKey, String secret) {
        try {
            PGPPublicKey pubKey = readPublicKey(publicKey);
            File secretFile = createTempSecretFile(secret);
            try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                writeFileToOutputStream(bos, secretFile, pubKey);
                return bos.toString("UTF-8").replaceAll(lineSeparator() + "Version: .+" + lineSeparator(), "");
            }
        } catch (IOException | PGPException e) {
            throw new JPGP2FAException(e);
        }
    }

    public static byte[] convertPublicKey(InputStream publicKey) {
        try {
            return readPublicKey(publicKey).getEncoded(true);
        } catch (IOException | PGPException e) {
            throw new JPGP2FAException(e);
        }
    }

    public static byte[] createRandomPublicKey() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096);
            return keyGen.generateKeyPair().getPublic().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new JPGP2FAException(e);
        }
    }

    private static File createTempSecretFile(String secret) throws IOException {
        File temp = File.createTempFile(randomUUID().toString(), null);
        try (FileWriter writer = new FileWriter(temp)) {
            writer.write(secret.toCharArray());
            return temp;
        }
    }

    private static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException, JPGP2FAException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(getDecoderStream(input), new JcaKeyFingerprintCalculator());

        List<PGPPublicKey> foo = asStream(pgpPub.getKeyRings())
                .flatMap(keyRing -> asStream(keyRing.getPublicKeys())).collect(toList());

        return asStream(pgpPub.getKeyRings())
                .flatMap(keyRing -> asStream(keyRing.getPublicKeys()))
                .filter(PGPPublicKey::isEncryptionKey)
                .findFirst()
                .orElseThrow(() -> new JPGP2FAException("Can't find encryption key in key ring."));
    }

    private static void writeFileToOutputStream(OutputStream out, File file, PGPPublicKey encKey) throws IOException, PGPException {
        try (
                ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);
                ByteArrayOutputStream bOut = new ByteArrayOutputStream()
        ) {
            writeFileToLiteralData(bOut, UTF8, file);
            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(CAST5));
            cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));
            byte[] bytes = bOut.toByteArray();
            try (OutputStream cOut = cPk.open(armoredOut, bytes.length)) {
                cOut.write(bytes);
            }
        }
    }

    private static <T> Stream<T> asStream(Iterator<T> iterator) {
        Iterable<T> iterable = () -> iterator;
        return stream(iterable.spliterator(), false);
    }
}
