package utils

func OfferSignatureDownload(ClientConfig *ClientConfig, version string) {
	// varDataPath := filepath.Join(ClientConfig.DataDir, version)
	// digestPath := filepath.Join(varDataPath, StandardizedQClientFileName+".dgst")
	// if FileExists(digestPath) {
	// 	// Fall back to checking next to executable
	// 	digestPath = ClientDataPath + "/" + version + "/" + StandardizedQClientFileName + ".dgst"
	// 	if !FileExists(digestPath) {
	// 		fmt.Println("Signature file not found. Would you like to download it? (y/n)")
	// 		reader := bufio.NewReader(os.Stdin)
	// 		response, _ := reader.ReadString('\n')
	// 		response = strings.TrimSpace(strings.ToLower(response))

	// 		if response == "y" || response == "yes" {
	// 			fmt.Println("Downloading signature files...")
	// 			if version == "" {
	// 				fmt.Println("Could not determine version from executable name")
	// 				return fmt.Errorf("could not determine version from executable name")
	// 			}

	// 			// Download signature files
	// 			if err := utils.DownloadReleaseSignatures(utils.ReleaseTypeQClient, version); err != nil {
	// 				fmt.Printf("Error downloading signature files: %v\n", err)
	// 				return fmt.Errorf("failed to download signature files: %v", err)
	// 			}
	// 			fmt.Println("Successfully downloaded signature files")
	// 		} else {
	// 			fmt.Println("Continuing without signature verification")
	// 			signatureCheck = false
	// 		}
	// 	}
	// }
}
