package com.encryption.app.encyption.util;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class EncryptionPgpUtil {
	public static byte[] encryptData(InputStream dataStream, InputStream keyStream) throws Exception {

		ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
//		PGPPublicKey key = "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sVXl";
		PGPPublicKey key = readKey(keyStream);
		OutputStream armoredOutputStream = new ArmoredOutputStream(encryptedData);
		

		PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
						.setSecureRandom(new SecureRandom()).setWithIntegrityPacket(true));
		pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key)
				.setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()));
		try {
			OutputStream op = pgpEncryptedDataGenerator.open(armoredOutputStream, new byte[1 << 16]);
			byte[] buffer = new byte[1024];
			int len;
			while ((len = dataStream.read(buffer)) != -1) {
				op.write(buffer, 0, len);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		armoredOutputStream.close();
		return encryptedData.toByteArray();

	}


	private static PGPPublicKey readKey(InputStream keyStream) throws Exception {
		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(keyStream), new JcaKeyFingerprintCalculator());
		for (PGPPublicKeyRing k : pgpPublicKeyRingCollection) {
			for (PGPPublicKey key : k) {
				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}
		throw new IllegalArgumentException("No key found");
	}

}
