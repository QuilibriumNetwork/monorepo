package protobufs

func SignatureMessageOf(m any) []byte {
	return m.(signatureMessage).signatureMessage()
}
