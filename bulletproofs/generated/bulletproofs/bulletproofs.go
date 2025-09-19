package bulletproofs

// #include <bulletproofs.h>
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
		C.ffi_bulletproofs_rustbuffer_free(cb, status)
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
		return C.ffi_bulletproofs_rustbuffer_from_bytes(foreign, status)
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
		return C.ffi_bulletproofs_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("bulletproofs: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_alt_generator(uniffiStatus)
		})
		if checksum != 26422 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_alt_generator: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_generate_input_commitments(uniffiStatus)
		})
		if checksum != 65001 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_generate_input_commitments: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_generate_range_proof(uniffiStatus)
		})
		if checksum != 40322 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_generate_range_proof: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_hash_to_scalar(uniffiStatus)
		})
		if checksum != 19176 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_hash_to_scalar: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_keygen(uniffiStatus)
		})
		if checksum != 46171 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_keygen: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_point_addition(uniffiStatus)
		})
		if checksum != 6828 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_point_addition: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_point_subtraction(uniffiStatus)
		})
		if checksum != 48479 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_point_subtraction: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_scalar_addition(uniffiStatus)
		})
		if checksum != 29576 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_scalar_addition: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_scalar_inverse(uniffiStatus)
		})
		if checksum != 11499 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_scalar_inverse: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_scalar_mult(uniffiStatus)
		})
		if checksum != 6075 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_scalar_mult: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_scalar_mult_hash_to_scalar(uniffiStatus)
		})
		if checksum != 53652 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_scalar_mult_hash_to_scalar: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_scalar_mult_point(uniffiStatus)
		})
		if checksum != 46237 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_scalar_mult_point: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_scalar_subtraction(uniffiStatus)
		})
		if checksum != 13728 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_scalar_subtraction: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_scalar_to_point(uniffiStatus)
		})
		if checksum != 61077 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_scalar_to_point: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_sign_hidden(uniffiStatus)
		})
		if checksum != 57560 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_sign_hidden: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_sign_simple(uniffiStatus)
		})
		if checksum != 5535 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_sign_simple: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_sum_check(uniffiStatus)
		})
		if checksum != 18164 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_sum_check: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_verify_hidden(uniffiStatus)
		})
		if checksum != 55266 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_verify_hidden: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_verify_range_proof(uniffiStatus)
		})
		if checksum != 37611 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_verify_range_proof: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bulletproofs_checksum_func_verify_simple(uniffiStatus)
		})
		if checksum != 32821 {
			// If this happens try cleaning and rebuilding your project
			panic("bulletproofs: uniffi_bulletproofs_checksum_func_verify_simple: UniFFI API checksum mismatch")
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

type RangeProofResult struct {
	Proof      []uint8
	Commitment []uint8
	Blinding   []uint8
}

func (r *RangeProofResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.Proof)
	FfiDestroyerSequenceUint8{}.Destroy(r.Commitment)
	FfiDestroyerSequenceUint8{}.Destroy(r.Blinding)
}

type FfiConverterTypeRangeProofResult struct{}

var FfiConverterTypeRangeProofResultINSTANCE = FfiConverterTypeRangeProofResult{}

func (c FfiConverterTypeRangeProofResult) Lift(rb RustBufferI) RangeProofResult {
	return LiftFromRustBuffer[RangeProofResult](c, rb)
}

func (c FfiConverterTypeRangeProofResult) Read(reader io.Reader) RangeProofResult {
	return RangeProofResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeRangeProofResult) Lower(value RangeProofResult) RustBuffer {
	return LowerIntoRustBuffer[RangeProofResult](c, value)
}

func (c FfiConverterTypeRangeProofResult) Write(writer io.Writer, value RangeProofResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Proof)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Commitment)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Blinding)
}

type FfiDestroyerTypeRangeProofResult struct{}

func (_ FfiDestroyerTypeRangeProofResult) Destroy(value RangeProofResult) {
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

func AltGenerator() []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_alt_generator(_uniffiStatus)
	}))
}

func GenerateInputCommitments(values [][]uint8, blinding []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_generate_input_commitments(FfiConverterSequenceSequenceUint8INSTANCE.Lower(values), FfiConverterSequenceUint8INSTANCE.Lower(blinding), _uniffiStatus)
	}))
}

func GenerateRangeProof(values [][]uint8, blinding []uint8, bitSize uint64) RangeProofResult {
	return FfiConverterTypeRangeProofResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_generate_range_proof(FfiConverterSequenceSequenceUint8INSTANCE.Lower(values), FfiConverterSequenceUint8INSTANCE.Lower(blinding), FfiConverterUint64INSTANCE.Lower(bitSize), _uniffiStatus)
	}))
}

func HashToScalar(input []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_hash_to_scalar(FfiConverterSequenceUint8INSTANCE.Lower(input), _uniffiStatus)
	}))
}

func Keygen() []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_keygen(_uniffiStatus)
	}))
}

func PointAddition(inputPoint []uint8, publicPoint []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_point_addition(FfiConverterSequenceUint8INSTANCE.Lower(inputPoint), FfiConverterSequenceUint8INSTANCE.Lower(publicPoint), _uniffiStatus)
	}))
}

func PointSubtraction(inputPoint []uint8, publicPoint []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_point_subtraction(FfiConverterSequenceUint8INSTANCE.Lower(inputPoint), FfiConverterSequenceUint8INSTANCE.Lower(publicPoint), _uniffiStatus)
	}))
}

func ScalarAddition(lhs []uint8, rhs []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_scalar_addition(FfiConverterSequenceUint8INSTANCE.Lower(lhs), FfiConverterSequenceUint8INSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func ScalarInverse(inputScalar []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_scalar_inverse(FfiConverterSequenceUint8INSTANCE.Lower(inputScalar), _uniffiStatus)
	}))
}

func ScalarMult(lhs []uint8, rhs []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_scalar_mult(FfiConverterSequenceUint8INSTANCE.Lower(lhs), FfiConverterSequenceUint8INSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func ScalarMultHashToScalar(inputScalar []uint8, publicPoint []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_scalar_mult_hash_to_scalar(FfiConverterSequenceUint8INSTANCE.Lower(inputScalar), FfiConverterSequenceUint8INSTANCE.Lower(publicPoint), _uniffiStatus)
	}))
}

func ScalarMultPoint(inputScalar []uint8, publicPoint []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_scalar_mult_point(FfiConverterSequenceUint8INSTANCE.Lower(inputScalar), FfiConverterSequenceUint8INSTANCE.Lower(publicPoint), _uniffiStatus)
	}))
}

func ScalarSubtraction(lhs []uint8, rhs []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_scalar_subtraction(FfiConverterSequenceUint8INSTANCE.Lower(lhs), FfiConverterSequenceUint8INSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func ScalarToPoint(input []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_scalar_to_point(FfiConverterSequenceUint8INSTANCE.Lower(input), _uniffiStatus)
	}))
}

func SignHidden(x []uint8, t []uint8, a []uint8, r []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_sign_hidden(FfiConverterSequenceUint8INSTANCE.Lower(x), FfiConverterSequenceUint8INSTANCE.Lower(t), FfiConverterSequenceUint8INSTANCE.Lower(a), FfiConverterSequenceUint8INSTANCE.Lower(r), _uniffiStatus)
	}))
}

func SignSimple(secret []uint8, message []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bulletproofs_fn_func_sign_simple(FfiConverterSequenceUint8INSTANCE.Lower(secret), FfiConverterSequenceUint8INSTANCE.Lower(message), _uniffiStatus)
	}))
}

func SumCheck(inputCommitments [][]uint8, additionalInputValues [][]uint8, outputCommitments [][]uint8, additionalOutputValues [][]uint8) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_bulletproofs_fn_func_sum_check(FfiConverterSequenceSequenceUint8INSTANCE.Lower(inputCommitments), FfiConverterSequenceSequenceUint8INSTANCE.Lower(additionalInputValues), FfiConverterSequenceSequenceUint8INSTANCE.Lower(outputCommitments), FfiConverterSequenceSequenceUint8INSTANCE.Lower(additionalOutputValues), _uniffiStatus)
	}))
}

func VerifyHidden(c []uint8, t []uint8, s1 []uint8, s2 []uint8, s3 []uint8, pPoint []uint8, cPoint []uint8) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_bulletproofs_fn_func_verify_hidden(FfiConverterSequenceUint8INSTANCE.Lower(c), FfiConverterSequenceUint8INSTANCE.Lower(t), FfiConverterSequenceUint8INSTANCE.Lower(s1), FfiConverterSequenceUint8INSTANCE.Lower(s2), FfiConverterSequenceUint8INSTANCE.Lower(s3), FfiConverterSequenceUint8INSTANCE.Lower(pPoint), FfiConverterSequenceUint8INSTANCE.Lower(cPoint), _uniffiStatus)
	}))
}

func VerifyRangeProof(proof []uint8, commitment []uint8, bitSize uint64) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_bulletproofs_fn_func_verify_range_proof(FfiConverterSequenceUint8INSTANCE.Lower(proof), FfiConverterSequenceUint8INSTANCE.Lower(commitment), FfiConverterUint64INSTANCE.Lower(bitSize), _uniffiStatus)
	}))
}

func VerifySimple(message []uint8, signature []uint8, publicPoint []uint8) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_bulletproofs_fn_func_verify_simple(FfiConverterSequenceUint8INSTANCE.Lower(message), FfiConverterSequenceUint8INSTANCE.Lower(signature), FfiConverterSequenceUint8INSTANCE.Lower(publicPoint), _uniffiStatus)
	}))
}
