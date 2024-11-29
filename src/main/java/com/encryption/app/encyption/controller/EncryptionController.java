package com.encryption.app.encyption.controller;

import java.io.FileOutputStream;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.encryption.app.encyption.util.EncryptionPgpUtil;

@RestController
@RequestMapping("/api/encrypt")
public class EncryptionController {
	
	@PostMapping("/file")
	public ResponseEntity<byte[]> upload(@RequestParam("file") MultipartFile file, @RequestParam("keyFile") MultipartFile keyFile){
		try {
			 
			byte[] encData = EncryptionPgpUtil.encryptData(file.getInputStream(), keyFile.getInputStream());  
	             FileOutputStream fout=new FileOutputStream("C:\\Users\\10821283\\Desktop\\testout.txt");    
	             fout.write(encData);    
	             fout.close();    
			return ResponseEntity.ok().body(encData);
		}
		catch (Exception e){
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	}
}
