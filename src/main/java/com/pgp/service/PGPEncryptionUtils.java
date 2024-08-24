package com.pgp.service;


import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.encoders.DecoderException;

import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.zip.GZIPInputStream;
public class PGPEncryptionUtils {
private static final int BUFFER_SIZE = 1 << 16; // 64K
	
	private static final int READ_AHEAD = 60;

	public static void encryptFile(String inputFileName, String outputFileName, PGPPublicKey publicKey, boolean armor)
			throws IOException, PGPException {
		try (OutputStream fileout = new BufferedOutputStream(new FileOutputStream(outputFileName))) {
			OutputStream out = fileout;
			if (armor) {
				out = new ArmoredOutputStream(out);
			}

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(inputFileName));
			comData.close();

			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
							.setSecureRandom(new SecureRandom()));

			encGen.addMethod(
					new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setSecureRandom(new SecureRandom()));

			byte[] bytes = bOut.toByteArray();

			OutputStream cOut = encGen.open(out, bytes.length);
			cOut.write(bytes);
			cOut.close();

			out.close();
		}
	}

	private static void writeFileToLiteralData(OutputStream out, char fileType, File file) throws IOException {
	    PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
	    try (OutputStream pOut = lData.open(out, fileType, file.getName(), file.length(), new java.util.Date());
	         FileInputStream in = new FileInputStream(file)) {
	        byte[] buf = new byte[BUFFER_SIZE];
	        int len;
	        while ((len = in.read(buf)) > 0) {
	            pOut.write(buf, 0, len);
	        }
	    } finally {
	        // Ensure the PGPLiteralDataGenerator is closed to avoid resource leaks
	        lData.close();
	    }
	}

	public static void decryptFile(String inputFileName, String outputFileName, PGPPrivateKey privateKey)
			throws IOException, PGPException {
		FileInputStream fs = new FileInputStream(inputFileName);
		
		// Use try-with-resources to ensure all resources are properly closed
		try (InputStream in = new BufferedInputStream(fs);
				InputStream decoderStream = PGPUtil.getDecoderStream(in)) {
			
			PGPObjectFactory pgpF = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
			PGPEncryptedDataList enc;

			Object o = pgpF.nextObject();
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

			Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;

			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();
				sKey = privateKey;
			}

			if (sKey == null) {
				throw new IllegalArgumentException("Secret key for message not found.");
			}

			// Process the decrypted stream
			try (InputStream clear = pbe
					.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey))) {

				PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
				Object message = plainFact.nextObject();

				if (message instanceof PGPCompressedData) {
					PGPCompressedData cData = (PGPCompressedData) message;
					PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(),
							new JcaKeyFingerprintCalculator());
					message = pgpFact.nextObject();
				}

				if (message instanceof PGPLiteralData) {
					PGPLiteralData ld = (PGPLiteralData) message;
					try (InputStream unc = ld.getInputStream();
							OutputStream fileOut = new BufferedOutputStream(new FileOutputStream(outputFileName))) {

						byte[] buf = new byte[BUFFER_SIZE];
						int len;
						while ((len = unc.read(buf)) > 0) {
							fileOut.write(buf, 0, len);
						}
					}
				} else if (message instanceof PGPOnePassSignatureList) {
					throw new PGPException("Encrypted message contains a signed message - not literal data.");
				} else {
					throw new PGPException("Message is not a simple encrypted file - type unknown.");
				}

				if (pbe.isIntegrityProtected() && !pbe.verify()) {
					throw new PGPException("Message failed integrity check");
				}
			}
			fs.close();
		}catch(Exception e) {
			fs.close();
			throw new PGPException("ISSUE WHILE DECRYPT");
		}
	}

	public static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
		try {
		InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
				new JcaKeyFingerprintCalculator());
		keyIn.close();

		Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPPublicKeyRing keyRing = keyRingIter.next();
			Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
			while (keyIter.hasNext()) {
				PGPPublicKey key = keyIter.next();
				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}}catch(Exception e) {
			e.printStackTrace();
		}
		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}
	
    private static InputStream getDecoderStream(InputStream in) throws IOException {
        return PGPUtil.getDecoderStream(in);
    }

	public static PGPPrivateKey findSecretKey(String fileName, long keyID, char[] pass)
			throws IOException, PGPException {
		InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
				new JcaKeyFingerprintCalculator());
		keyIn.close();

		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(
				new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).build(pass));
	}
	
    public static InputStream getCustomDecoderStream(InputStream in) throws IOException {
        // Attempt to decode and decompress the input stream
        InputStream resultStream = in;
        
        // Check if it's Base64 encoded and decode it
        resultStream = tryBase64Decode(resultStream);

        // Check if it's GZIP compressed and decompress it
        resultStream = tryGzipDecompress(resultStream);

        return resultStream;
    }

    private static InputStream tryBase64Decode(InputStream in) throws IOException {
        byte[] data = in.readAllBytes();

        // Heuristic: Base64 encoded data often ends with '=' padding
        boolean isBase64 = data.length > 0 && (data[data.length - 1] == '=' || isBase64Encoded(data));
        
        if (isBase64) {
            try {
                byte[] decodedData = Base64.getDecoder().decode(data);
                return new ByteArrayInputStream(decodedData);
            } catch (IllegalArgumentException e) {
                // Not base64, return the original stream
                return new ByteArrayInputStream(data);
            }
        } else {
            // Return the original stream if not base64
            return new ByteArrayInputStream(data);
        }
    }

    private static boolean isBase64Encoded(byte[] data) {
        // Heuristic: check if most bytes are within the ASCII range for Base64 characters
        for (byte b : data) {
            if ((b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '+' && b != '/' && b != '=') {
                return false;
            }
        }
        return true;
    }

    private static InputStream tryGzipDecompress(InputStream in) throws IOException {
        try {
            // Wrap in GZIPInputStream to test if it is actually GZIP-compressed
            return new GZIPInputStream(in);
        } catch (IOException e) {
            // If it's not GZIP, return the original input stream
            return in;
        }
    }

	public static InputStream getDecoderStream2(InputStream in) throws IOException {
		if (!in.markSupported()) {
			in = new BufferedInputStreamExt(in);
		}

		in.mark(READ_AHEAD);

		int ch = in.read();

		if ((ch & 0x80) != 0) {
			in.reset();

			return in;
		} else {
			if (!isPossiblyBase64(ch)) {
				in.reset();

				return new ArmoredInputStream(in);
			}

			byte[] buf = new byte[READ_AHEAD];
			int count = 1;
			int index = 1;

			buf[0] = (byte) ch;
			while (count != READ_AHEAD && (ch = in.read()) >= 0) {
				if (!isPossiblyBase64(ch)) {
					in.reset();

					return new ArmoredInputStream(in);
				}

				if (ch != '\n' && ch != '\r') {
					buf[index++] = (byte) ch;
				}

				count++;
			}

			in.reset();

			//
			// nothing but new lines, little else, assume regular armoring
			//
			if (count < 4) {
				return new ArmoredInputStream(in);
			}

			//
			// test our non-blank data
			//
			byte[] firstBlock = new byte[8];

			System.arraycopy(buf, 0, firstBlock, 0, firstBlock.length);

			try {
				byte[] decoded = org.bouncycastle.util.encoders.Base64.decode(firstBlock);

				//
				// it's a base64 PGP block.
				//
				if ((decoded[0] & 0x80) != 0) {
					return new ArmoredInputStream(in, false);
				}

				return new ArmoredInputStream(in);
			} catch (DecoderException e) {
				throw new IOException(e.getMessage());
			}
		}
	}

	static class BufferedInputStreamExt extends BufferedInputStream {
		BufferedInputStreamExt(InputStream input) {
			super(input);
		}

		public synchronized int available() throws IOException {
			int result = super.available();
			if (result < 0) {
				result = Integer.MAX_VALUE;
			}
			return result;
		}
	}
	
	private static boolean isPossiblyBase64(int ch) {
		return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch == '+')
				|| (ch == '/') || (ch == '\r') || (ch == '\n');
	}
}
