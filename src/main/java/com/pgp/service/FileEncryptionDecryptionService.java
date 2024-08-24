package com.pgp.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.mock.web.MockMultipartFile;

@Service
public class FileEncryptionDecryptionService {

	@Value("${security.asymmetric.privatekey}")
	private String privateKeyPath;

	@Value("${security.asymmetric.publickey}")
	private String publicKeyPath;

	public MultipartFile encryptMultiPartFile(MultipartFile file) throws IOException, PGPException {
		// Create a temporary directory for processing
		Path tempDir = Files.createTempDirectory("file-encrypt-temp");
		try {
			String originalFilePath = tempDir.resolve(file.getOriginalFilename()).toString();
			String encryptedFilePath = originalFilePath.replace(".txt", ".pgp");

			// Save the original file in the temporary directory
			file.transferTo(new File(originalFilePath));

			PGPPublicKey publicKey = PGPEncryptionUtils.readPublicKey(publicKeyPath);
			PGPEncryptionUtils.encryptFile(originalFilePath, encryptedFilePath, publicKey, true);

			// Read the encrypted file into a MultipartFile
			File encryptedFile = new File(encryptedFilePath);
			return convertFileToMultipartFile(encryptedFile);
		} finally {
			// Cleanup: remove the temporary directory and its contents
			deleteDirectory(tempDir.toFile());
		}
	}

	public MultipartFile decryptMultiPartFile(MultipartFile file) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		// Create a temporary directory for processing
		Path tempDir = Files.createTempDirectory("file-decrypt-temp");
		try {
			String encryptedFilePath = tempDir.resolve(file.getOriginalFilename()).toString();
			String decryptedFilePath = encryptedFilePath.replace(".pgp", ".txt");
			String decPhrase = "1234567890";

			// Save the encrypted file in the temporary directory
			file.transferTo(new File(encryptedFilePath));

			long keyId = getKeyId(encryptedFilePath);
			if (keyId == 0L) {
				throw new Exception("KEY ID NOT FOUND");
			}
			try {
				PGPPrivateKey privateKey = PGPEncryptionUtils.findSecretKey(privateKeyPath, keyId,
						decPhrase.toCharArray());
				PGPEncryptionUtils.decryptFile(encryptedFilePath, decryptedFilePath, privateKey);

				// Read the decrypted file into a MultipartFile
				File decryptedFile = new File(decryptedFilePath);
				return convertFileToMultipartFile(decryptedFile);
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}

		} finally {
			// Cleanup: remove the temporary directory and its contents
			deleteDirectory(tempDir.toFile());
		}
	}

	private void deleteDirectory(File directory) {
		if (directory.isDirectory()) {
			for (File file : directory.listFiles()) {
				deleteDirectory(file);
			}
		}
		directory.delete();
	}

	private MultipartFile convertFileToMultipartFile(File file) throws IOException {
		FileInputStream input = new FileInputStream(file);
		try {
			return new MockMultipartFile(file.getName(), file.getName(), Files.probeContentType(file.toPath()), input);
		} finally {
			input.close();
		}
	}

	private long getKeyId(String pgpFilePath) {
		try (InputStream in = new FileInputStream(pgpFilePath)) {
			ArmoredInputStream aIn = new ArmoredInputStream(in);
			InputStream decodedIn = PGPUtil.getDecoderStream(aIn);

			PGPObjectFactory pgpFactory = new JcaPGPObjectFactory(decodedIn);
			Object object = pgpFactory.nextObject();

			if (object instanceof PGPEncryptedDataList) {
				PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) object;
				PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.get(0);

				long keyId = encryptedData.getKeyID();
				return keyId;
			} else {
				return 0L;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return 0L;
	}
}