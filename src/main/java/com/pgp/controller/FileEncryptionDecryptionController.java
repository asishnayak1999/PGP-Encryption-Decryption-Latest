package com.pgp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.pgp.service.FileEncryptionDecryptionService;

@CrossOrigin
@RestController
@RequestMapping("/pgp/fileencryption")
public class FileEncryptionDecryptionController {

	@Autowired
	private FileEncryptionDecryptionService fileEncryptionDecryptionService;

	@PostMapping("/process")
	public ResponseEntity<byte[]> processFile(@RequestParam("file") MultipartFile file) {
		String fileName = file.getOriginalFilename();
		if (fileName == null) {
			return ResponseEntity.badRequest().build();
		}
		try {
			MultipartFile processedFile;
			if (fileName.endsWith(".txt")) {
				processedFile = fileEncryptionDecryptionService.encryptMultiPartFile(file);
			} else if (fileName.endsWith(".pgp")) {
				processedFile = fileEncryptionDecryptionService.decryptMultiPartFile(file);
			} else {
				return ResponseEntity.badRequest().build();
			}
			return ResponseEntity.ok()
					.header(HttpHeaders.CONTENT_DISPOSITION,
							"attachment; filename=\"" + processedFile.getOriginalFilename() + "\"")
					.contentType(MediaType.APPLICATION_OCTET_STREAM).body(processedFile.getBytes());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}
}