package verenc

// #include <verenc.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"unsafe"
)

type RustBuffer = C.RustBuffer

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() int
	Capacity() int
}

func RustBufferFromExternal(b RustBufferI) RustBuffer {
	return RustBuffer{
		capacity: C.int(b.Capacity()),
		len:      C.int(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func (cb RustBuffer) Capacity() int {
	return int(cb.capacity)
}

func (cb RustBuffer) Len() int {
	return int(cb.len)
}

func (cb RustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.data)
}

func (cb RustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.data), C.int(cb.len))
	return bytes.NewReader(b)
}

func (cb RustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_verenc_rustbuffer_free(cb, status)
		return false
	})
}

func (cb RustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.data), C.int(cb.len))
}

func stringToRustBuffer(str string) RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) RustBuffer {
	if len(b) == 0 {
		return RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) RustBuffer {
		return C.ffi_verenc_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) RustBuffer
}

type FfiConverter[GoType any, FfiType any] interface {
	Lift(value FfiType) GoType
	Lower(value GoType) FfiType
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

type FfiRustBufConverter[GoType any, FfiType any] interface {
	FfiConverter[GoType, FfiType]
	BufReader[GoType]
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[U any](converter BufLifter[error], callback func(*C.RustCallStatus) U) (U, error) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)

	return returnValue, err
}

func checkCallStatus(converter BufLifter[error], status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		return converter.Lift(status.errorBuf)
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(status.errorBuf)))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(status.errorBuf)))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError(nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 24
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_verenc_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("verenc: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_chunk_data_for_verenc(uniffiStatus)
		})
		if checksum != 16794 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_chunk_data_for_verenc: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_combine_chunked_data(uniffiStatus)
		})
		if checksum != 28541 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_combine_chunked_data: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_new_verenc_proof(uniffiStatus)
		})
		if checksum != 7394 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_new_verenc_proof: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_new_verenc_proof_encrypt_only(uniffiStatus)
		})
		if checksum != 17751 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_new_verenc_proof_encrypt_only: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_verenc_compress(uniffiStatus)
		})
		if checksum != 11234 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_verenc_compress: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_verenc_recover(uniffiStatus)
		})
		if checksum != 38626 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_verenc_recover: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_verenc_verify(uniffiStatus)
		})
		if checksum != 51440 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_verenc_verify: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint8 struct{}

var FfiConverterUint8INSTANCE = FfiConverterUint8{}

func (FfiConverterUint8) Lower(value uint8) C.uint8_t {
	return C.uint8_t(value)
}

func (FfiConverterUint8) Write(writer io.Writer, value uint8) {
	writeUint8(writer, value)
}

func (FfiConverterUint8) Lift(value C.uint8_t) uint8 {
	return uint8(value)
}

func (FfiConverterUint8) Read(reader io.Reader) uint8 {
	return readUint8(reader)
}

type FfiDestroyerUint8 struct{}

func (FfiDestroyerUint8) Destroy(_ uint8) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct{}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type CompressedCiphertext struct {
	Ctexts []VerencCiphertext
	Aux    [][]uint8
}

func (r *CompressedCiphertext) Destroy() {
	FfiDestroyerSequenceTypeVerencCiphertext{}.Destroy(r.Ctexts)
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.Aux)
}

type FfiConverterTypeCompressedCiphertext struct{}

var FfiConverterTypeCompressedCiphertextINSTANCE = FfiConverterTypeCompressedCiphertext{}

func (c FfiConverterTypeCompressedCiphertext) Lift(rb RustBufferI) CompressedCiphertext {
	return LiftFromRustBuffer[CompressedCiphertext](c, rb)
}

func (c FfiConverterTypeCompressedCiphertext) Read(reader io.Reader) CompressedCiphertext {
	return CompressedCiphertext{
		FfiConverterSequenceTypeVerencCiphertextINSTANCE.Read(reader),
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeCompressedCiphertext) Lower(value CompressedCiphertext) RustBuffer {
	return LowerIntoRustBuffer[CompressedCiphertext](c, value)
}

func (c FfiConverterTypeCompressedCiphertext) Write(writer io.Writer, value CompressedCiphertext) {
	FfiConverterSequenceTypeVerencCiphertextINSTANCE.Write(writer, value.Ctexts)
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.Aux)
}

type FfiDestroyerTypeCompressedCiphertext struct{}

func (_ FfiDestroyerTypeCompressedCiphertext) Destroy(value CompressedCiphertext) {
	value.Destroy()
}

type VerencCiphertext struct {
	C1 []uint8
	C2 []uint8
	I  uint64
}

func (r *VerencCiphertext) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.C1)
	FfiDestroyerSequenceUint8{}.Destroy(r.C2)
	FfiDestroyerUint64{}.Destroy(r.I)
}

type FfiConverterTypeVerencCiphertext struct{}

var FfiConverterTypeVerencCiphertextINSTANCE = FfiConverterTypeVerencCiphertext{}

func (c FfiConverterTypeVerencCiphertext) Lift(rb RustBufferI) VerencCiphertext {
	return LiftFromRustBuffer[VerencCiphertext](c, rb)
}

func (c FfiConverterTypeVerencCiphertext) Read(reader io.Reader) VerencCiphertext {
	return VerencCiphertext{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeVerencCiphertext) Lower(value VerencCiphertext) RustBuffer {
	return LowerIntoRustBuffer[VerencCiphertext](c, value)
}

func (c FfiConverterTypeVerencCiphertext) Write(writer io.Writer, value VerencCiphertext) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.C1)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.C2)
	FfiConverterUint64INSTANCE.Write(writer, value.I)
}

type FfiDestroyerTypeVerencCiphertext struct{}

func (_ FfiDestroyerTypeVerencCiphertext) Destroy(value VerencCiphertext) {
	value.Destroy()
}

type VerencDecrypt struct {
	BlindingPubkey []uint8
	DecryptionKey  []uint8
	Statement      []uint8
	Ciphertexts    CompressedCiphertext
}

func (r *VerencDecrypt) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingPubkey)
	FfiDestroyerSequenceUint8{}.Destroy(r.DecryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.Statement)
	FfiDestroyerTypeCompressedCiphertext{}.Destroy(r.Ciphertexts)
}

type FfiConverterTypeVerencDecrypt struct{}

var FfiConverterTypeVerencDecryptINSTANCE = FfiConverterTypeVerencDecrypt{}

func (c FfiConverterTypeVerencDecrypt) Lift(rb RustBufferI) VerencDecrypt {
	return LiftFromRustBuffer[VerencDecrypt](c, rb)
}

func (c FfiConverterTypeVerencDecrypt) Read(reader io.Reader) VerencDecrypt {
	return VerencDecrypt{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterTypeCompressedCiphertextINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeVerencDecrypt) Lower(value VerencDecrypt) RustBuffer {
	return LowerIntoRustBuffer[VerencDecrypt](c, value)
}

func (c FfiConverterTypeVerencDecrypt) Write(writer io.Writer, value VerencDecrypt) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingPubkey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.DecryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Statement)
	FfiConverterTypeCompressedCiphertextINSTANCE.Write(writer, value.Ciphertexts)
}

type FfiDestroyerTypeVerencDecrypt struct{}

func (_ FfiDestroyerTypeVerencDecrypt) Destroy(value VerencDecrypt) {
	value.Destroy()
}

type VerencProof struct {
	BlindingPubkey []uint8
	EncryptionKey  []uint8
	Statement      []uint8
	Challenge      []uint8
	Polycom        [][]uint8
	Ctexts         []VerencCiphertext
	SharesRands    []VerencShare
}

func (r *VerencProof) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingPubkey)
	FfiDestroyerSequenceUint8{}.Destroy(r.EncryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.Statement)
	FfiDestroyerSequenceUint8{}.Destroy(r.Challenge)
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.Polycom)
	FfiDestroyerSequenceTypeVerencCiphertext{}.Destroy(r.Ctexts)
	FfiDestroyerSequenceTypeVerencShare{}.Destroy(r.SharesRands)
}

type FfiConverterTypeVerencProof struct{}

var FfiConverterTypeVerencProofINSTANCE = FfiConverterTypeVerencProof{}

func (c FfiConverterTypeVerencProof) Lift(rb RustBufferI) VerencProof {
	return LiftFromRustBuffer[VerencProof](c, rb)
}

func (c FfiConverterTypeVerencProof) Read(reader io.Reader) VerencProof {
	return VerencProof{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceTypeVerencCiphertextINSTANCE.Read(reader),
		FfiConverterSequenceTypeVerencShareINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeVerencProof) Lower(value VerencProof) RustBuffer {
	return LowerIntoRustBuffer[VerencProof](c, value)
}

func (c FfiConverterTypeVerencProof) Write(writer io.Writer, value VerencProof) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingPubkey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.EncryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Statement)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Challenge)
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.Polycom)
	FfiConverterSequenceTypeVerencCiphertextINSTANCE.Write(writer, value.Ctexts)
	FfiConverterSequenceTypeVerencShareINSTANCE.Write(writer, value.SharesRands)
}

type FfiDestroyerTypeVerencProof struct{}

func (_ FfiDestroyerTypeVerencProof) Destroy(value VerencProof) {
	value.Destroy()
}

type VerencProofAndBlindingKey struct {
	BlindingKey    []uint8
	BlindingPubkey []uint8
	DecryptionKey  []uint8
	EncryptionKey  []uint8
	Statement      []uint8
	Challenge      []uint8
	Polycom        [][]uint8
	Ctexts         []VerencCiphertext
	SharesRands    []VerencShare
}

func (r *VerencProofAndBlindingKey) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingPubkey)
	FfiDestroyerSequenceUint8{}.Destroy(r.DecryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.EncryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.Statement)
	FfiDestroyerSequenceUint8{}.Destroy(r.Challenge)
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.Polycom)
	FfiDestroyerSequenceTypeVerencCiphertext{}.Destroy(r.Ctexts)
	FfiDestroyerSequenceTypeVerencShare{}.Destroy(r.SharesRands)
}

type FfiConverterTypeVerencProofAndBlindingKey struct{}

var FfiConverterTypeVerencProofAndBlindingKeyINSTANCE = FfiConverterTypeVerencProofAndBlindingKey{}

func (c FfiConverterTypeVerencProofAndBlindingKey) Lift(rb RustBufferI) VerencProofAndBlindingKey {
	return LiftFromRustBuffer[VerencProofAndBlindingKey](c, rb)
}

func (c FfiConverterTypeVerencProofAndBlindingKey) Read(reader io.Reader) VerencProofAndBlindingKey {
	return VerencProofAndBlindingKey{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceTypeVerencCiphertextINSTANCE.Read(reader),
		FfiConverterSequenceTypeVerencShareINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeVerencProofAndBlindingKey) Lower(value VerencProofAndBlindingKey) RustBuffer {
	return LowerIntoRustBuffer[VerencProofAndBlindingKey](c, value)
}

func (c FfiConverterTypeVerencProofAndBlindingKey) Write(writer io.Writer, value VerencProofAndBlindingKey) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingPubkey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.DecryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.EncryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Statement)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Challenge)
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.Polycom)
	FfiConverterSequenceTypeVerencCiphertextINSTANCE.Write(writer, value.Ctexts)
	FfiConverterSequenceTypeVerencShareINSTANCE.Write(writer, value.SharesRands)
}

type FfiDestroyerTypeVerencProofAndBlindingKey struct{}

func (_ FfiDestroyerTypeVerencProofAndBlindingKey) Destroy(value VerencProofAndBlindingKey) {
	value.Destroy()
}

type VerencShare struct {
	S1 []uint8
	S2 []uint8
	I  uint64
}

func (r *VerencShare) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.S1)
	FfiDestroyerSequenceUint8{}.Destroy(r.S2)
	FfiDestroyerUint64{}.Destroy(r.I)
}

type FfiConverterTypeVerencShare struct{}

var FfiConverterTypeVerencShareINSTANCE = FfiConverterTypeVerencShare{}

func (c FfiConverterTypeVerencShare) Lift(rb RustBufferI) VerencShare {
	return LiftFromRustBuffer[VerencShare](c, rb)
}

func (c FfiConverterTypeVerencShare) Read(reader io.Reader) VerencShare {
	return VerencShare{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeVerencShare) Lower(value VerencShare) RustBuffer {
	return LowerIntoRustBuffer[VerencShare](c, value)
}

func (c FfiConverterTypeVerencShare) Write(writer io.Writer, value VerencShare) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.S1)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.S2)
	FfiConverterUint64INSTANCE.Write(writer, value.I)
}

type FfiDestroyerTypeVerencShare struct{}

func (_ FfiDestroyerTypeVerencShare) Destroy(value VerencShare) {
	value.Destroy()
}

type FfiConverterSequenceUint8 struct{}

var FfiConverterSequenceUint8INSTANCE = FfiConverterSequenceUint8{}

func (c FfiConverterSequenceUint8) Lift(rb RustBufferI) []uint8 {
	return LiftFromRustBuffer[[]uint8](c, rb)
}

func (c FfiConverterSequenceUint8) Read(reader io.Reader) []uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint8) Lower(value []uint8) RustBuffer {
	return LowerIntoRustBuffer[[]uint8](c, value)
}

func (c FfiConverterSequenceUint8) Write(writer io.Writer, value []uint8) {
	if len(value) > math.MaxInt32 {
		panic("[]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint8 struct{}

func (FfiDestroyerSequenceUint8) Destroy(sequence []uint8) {
	for _, value := range sequence {
		FfiDestroyerUint8{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeVerencCiphertext struct{}

var FfiConverterSequenceTypeVerencCiphertextINSTANCE = FfiConverterSequenceTypeVerencCiphertext{}

func (c FfiConverterSequenceTypeVerencCiphertext) Lift(rb RustBufferI) []VerencCiphertext {
	return LiftFromRustBuffer[[]VerencCiphertext](c, rb)
}

func (c FfiConverterSequenceTypeVerencCiphertext) Read(reader io.Reader) []VerencCiphertext {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]VerencCiphertext, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeVerencCiphertextINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeVerencCiphertext) Lower(value []VerencCiphertext) RustBuffer {
	return LowerIntoRustBuffer[[]VerencCiphertext](c, value)
}

func (c FfiConverterSequenceTypeVerencCiphertext) Write(writer io.Writer, value []VerencCiphertext) {
	if len(value) > math.MaxInt32 {
		panic("[]VerencCiphertext is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeVerencCiphertextINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeVerencCiphertext struct{}

func (FfiDestroyerSequenceTypeVerencCiphertext) Destroy(sequence []VerencCiphertext) {
	for _, value := range sequence {
		FfiDestroyerTypeVerencCiphertext{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeVerencShare struct{}

var FfiConverterSequenceTypeVerencShareINSTANCE = FfiConverterSequenceTypeVerencShare{}

func (c FfiConverterSequenceTypeVerencShare) Lift(rb RustBufferI) []VerencShare {
	return LiftFromRustBuffer[[]VerencShare](c, rb)
}

func (c FfiConverterSequenceTypeVerencShare) Read(reader io.Reader) []VerencShare {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]VerencShare, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeVerencShareINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeVerencShare) Lower(value []VerencShare) RustBuffer {
	return LowerIntoRustBuffer[[]VerencShare](c, value)
}

func (c FfiConverterSequenceTypeVerencShare) Write(writer io.Writer, value []VerencShare) {
	if len(value) > math.MaxInt32 {
		panic("[]VerencShare is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeVerencShareINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeVerencShare struct{}

func (FfiDestroyerSequenceTypeVerencShare) Destroy(sequence []VerencShare) {
	for _, value := range sequence {
		FfiDestroyerTypeVerencShare{}.Destroy(value)
	}
}

type FfiConverterSequenceSequenceUint8 struct{}

var FfiConverterSequenceSequenceUint8INSTANCE = FfiConverterSequenceSequenceUint8{}

func (c FfiConverterSequenceSequenceUint8) Lift(rb RustBufferI) [][]uint8 {
	return LiftFromRustBuffer[[][]uint8](c, rb)
}

func (c FfiConverterSequenceSequenceUint8) Read(reader io.Reader) [][]uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([][]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterSequenceUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceSequenceUint8) Lower(value [][]uint8) RustBuffer {
	return LowerIntoRustBuffer[[][]uint8](c, value)
}

func (c FfiConverterSequenceSequenceUint8) Write(writer io.Writer, value [][]uint8) {
	if len(value) > math.MaxInt32 {
		panic("[][]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterSequenceUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceSequenceUint8 struct{}

func (FfiDestroyerSequenceSequenceUint8) Destroy(sequence [][]uint8) {
	for _, value := range sequence {
		FfiDestroyerSequenceUint8{}.Destroy(value)
	}
}

func ChunkDataForVerenc(data []uint8) [][]uint8 {
	return FfiConverterSequenceSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_verenc_fn_func_chunk_data_for_verenc(FfiConverterSequenceUint8INSTANCE.Lower(data), _uniffiStatus)
	}))
}

func CombineChunkedData(chunks [][]uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_verenc_fn_func_combine_chunked_data(FfiConverterSequenceSequenceUint8INSTANCE.Lower(chunks), _uniffiStatus)
	}))
}

func NewVerencProof(data []uint8) VerencProofAndBlindingKey {
	return FfiConverterTypeVerencProofAndBlindingKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_verenc_fn_func_new_verenc_proof(FfiConverterSequenceUint8INSTANCE.Lower(data), _uniffiStatus)
	}))
}

func NewVerencProofEncryptOnly(data []uint8, encryptionKeyBytes []uint8) VerencProofAndBlindingKey {
	return FfiConverterTypeVerencProofAndBlindingKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_verenc_fn_func_new_verenc_proof_encrypt_only(FfiConverterSequenceUint8INSTANCE.Lower(data), FfiConverterSequenceUint8INSTANCE.Lower(encryptionKeyBytes), _uniffiStatus)
	}))
}

func VerencCompress(proof VerencProof) CompressedCiphertext {
	return FfiConverterTypeCompressedCiphertextINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_verenc_fn_func_verenc_compress(FfiConverterTypeVerencProofINSTANCE.Lower(proof), _uniffiStatus)
	}))
}

func VerencRecover(recovery VerencDecrypt) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_verenc_fn_func_verenc_recover(FfiConverterTypeVerencDecryptINSTANCE.Lower(recovery), _uniffiStatus)
	}))
}

func VerencVerify(proof VerencProof) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_verenc_fn_func_verenc_verify(FfiConverterTypeVerencProofINSTANCE.Lower(proof), _uniffiStatus)
	}))
}
