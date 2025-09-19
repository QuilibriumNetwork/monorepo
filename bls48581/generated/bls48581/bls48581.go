package bls48581

// #include <bls48581.h>
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
		C.ffi_bls48581_rustbuffer_free(cb, status)
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
		return C.ffi_bls48581_rustbuffer_from_bytes(foreign, status)
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
		return C.ffi_bls48581_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("bls48581: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_bls_aggregate(uniffiStatus)
		})
		if checksum != 25405 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_bls_aggregate: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_bls_keygen(uniffiStatus)
		})
		if checksum != 58096 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_bls_keygen: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_bls_sign(uniffiStatus)
		})
		if checksum != 44903 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_bls_sign: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_bls_verify(uniffiStatus)
		})
		if checksum != 59437 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_bls_verify: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_commit_raw(uniffiStatus)
		})
		if checksum != 20099 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_commit_raw: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_init(uniffiStatus)
		})
		if checksum != 11227 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_prove_multiple(uniffiStatus)
		})
		if checksum != 15323 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_prove_multiple: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_prove_raw(uniffiStatus)
		})
		if checksum != 64858 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_prove_raw: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_verify_multiple(uniffiStatus)
		})
		if checksum != 33757 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_verify_multiple: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bls48581_checksum_func_verify_raw(uniffiStatus)
		})
		if checksum != 52165 {
			// If this happens try cleaning and rebuilding your project
			panic("bls48581: uniffi_bls48581_checksum_func_verify_raw: UniFFI API checksum mismatch")
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

type BlsAggregateOutput struct {
	AggregatePublicKey []uint8
	AggregateSignature []uint8
}

func (r *BlsAggregateOutput) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.AggregatePublicKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.AggregateSignature)
}

type FfiConverterTypeBlsAggregateOutput struct{}

var FfiConverterTypeBlsAggregateOutputINSTANCE = FfiConverterTypeBlsAggregateOutput{}

func (c FfiConverterTypeBlsAggregateOutput) Lift(rb RustBufferI) BlsAggregateOutput {
	return LiftFromRustBuffer[BlsAggregateOutput](c, rb)
}

func (c FfiConverterTypeBlsAggregateOutput) Read(reader io.Reader) BlsAggregateOutput {
	return BlsAggregateOutput{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeBlsAggregateOutput) Lower(value BlsAggregateOutput) RustBuffer {
	return LowerIntoRustBuffer[BlsAggregateOutput](c, value)
}

func (c FfiConverterTypeBlsAggregateOutput) Write(writer io.Writer, value BlsAggregateOutput) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.AggregatePublicKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.AggregateSignature)
}

type FfiDestroyerTypeBlsAggregateOutput struct{}

func (_ FfiDestroyerTypeBlsAggregateOutput) Destroy(value BlsAggregateOutput) {
	value.Destroy()
}

type BlsKeygenOutput struct {
	SecretKey            []uint8
	PublicKey            []uint8
	ProofOfPossessionSig []uint8
}

func (r *BlsKeygenOutput) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SecretKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.PublicKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.ProofOfPossessionSig)
}

type FfiConverterTypeBlsKeygenOutput struct{}

var FfiConverterTypeBlsKeygenOutputINSTANCE = FfiConverterTypeBlsKeygenOutput{}

func (c FfiConverterTypeBlsKeygenOutput) Lift(rb RustBufferI) BlsKeygenOutput {
	return LiftFromRustBuffer[BlsKeygenOutput](c, rb)
}

func (c FfiConverterTypeBlsKeygenOutput) Read(reader io.Reader) BlsKeygenOutput {
	return BlsKeygenOutput{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeBlsKeygenOutput) Lower(value BlsKeygenOutput) RustBuffer {
	return LowerIntoRustBuffer[BlsKeygenOutput](c, value)
}

func (c FfiConverterTypeBlsKeygenOutput) Write(writer io.Writer, value BlsKeygenOutput) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SecretKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.PublicKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.ProofOfPossessionSig)
}

type FfiDestroyerTypeBlsKeygenOutput struct{}

func (_ FfiDestroyerTypeBlsKeygenOutput) Destroy(value BlsKeygenOutput) {
	value.Destroy()
}

type Multiproof struct {
	D     []uint8
	Proof []uint8
}

func (r *Multiproof) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.D)
	FfiDestroyerSequenceUint8{}.Destroy(r.Proof)
}

type FfiConverterTypeMultiproof struct{}

var FfiConverterTypeMultiproofINSTANCE = FfiConverterTypeMultiproof{}

func (c FfiConverterTypeMultiproof) Lift(rb RustBufferI) Multiproof {
	return LiftFromRustBuffer[Multiproof](c, rb)
}

func (c FfiConverterTypeMultiproof) Read(reader io.Reader) Multiproof {
	return Multiproof{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeMultiproof) Lower(value Multiproof) RustBuffer {
	return LowerIntoRustBuffer[Multiproof](c, value)
}

func (c FfiConverterTypeMultiproof) Write(writer io.Writer, value Multiproof) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.D)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Proof)
}

type FfiDestroyerTypeMultiproof struct{}

func (_ FfiDestroyerTypeMultiproof) Destroy(value Multiproof) {
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

type FfiConverterSequenceUint64 struct{}

var FfiConverterSequenceUint64INSTANCE = FfiConverterSequenceUint64{}

func (c FfiConverterSequenceUint64) Lift(rb RustBufferI) []uint64 {
	return LiftFromRustBuffer[[]uint64](c, rb)
}

func (c FfiConverterSequenceUint64) Read(reader io.Reader) []uint64 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint64, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint64INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint64) Lower(value []uint64) RustBuffer {
	return LowerIntoRustBuffer[[]uint64](c, value)
}

func (c FfiConverterSequenceUint64) Write(writer io.Writer, value []uint64) {
	if len(value) > math.MaxInt32 {
		panic("[]uint64 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint64INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint64 struct{}

func (FfiDestroyerSequenceUint64) Destroy(sequence []uint64) {
	for _, value := range sequence {
		FfiDestroyerUint64{}.Destroy(value)
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

func BlsAggregate(pks [][]uint8, sigs [][]uint8) BlsAggregateOutput {
	return FfiConverterTypeBlsAggregateOutputINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bls48581_fn_func_bls_aggregate(FfiConverterSequenceSequenceUint8INSTANCE.Lower(pks), FfiConverterSequenceSequenceUint8INSTANCE.Lower(sigs), _uniffiStatus)
	}))
}

func BlsKeygen() BlsKeygenOutput {
	return FfiConverterTypeBlsKeygenOutputINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bls48581_fn_func_bls_keygen(_uniffiStatus)
	}))
}

func BlsSign(sk []uint8, msg []uint8, domain []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bls48581_fn_func_bls_sign(FfiConverterSequenceUint8INSTANCE.Lower(sk), FfiConverterSequenceUint8INSTANCE.Lower(msg), FfiConverterSequenceUint8INSTANCE.Lower(domain), _uniffiStatus)
	}))
}

func BlsVerify(pk []uint8, sig []uint8, msg []uint8, domain []uint8) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_bls48581_fn_func_bls_verify(FfiConverterSequenceUint8INSTANCE.Lower(pk), FfiConverterSequenceUint8INSTANCE.Lower(sig), FfiConverterSequenceUint8INSTANCE.Lower(msg), FfiConverterSequenceUint8INSTANCE.Lower(domain), _uniffiStatus)
	}))
}

func CommitRaw(data []uint8, polySize uint64) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bls48581_fn_func_commit_raw(FfiConverterSequenceUint8INSTANCE.Lower(data), FfiConverterUint64INSTANCE.Lower(polySize), _uniffiStatus)
	}))
}

func Init() {
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_bls48581_fn_func_init(_uniffiStatus)
		return false
	})
}

func ProveMultiple(commitments [][]uint8, polys [][]uint8, indices []uint64, polySize uint64) Multiproof {
	return FfiConverterTypeMultiproofINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bls48581_fn_func_prove_multiple(FfiConverterSequenceSequenceUint8INSTANCE.Lower(commitments), FfiConverterSequenceSequenceUint8INSTANCE.Lower(polys), FfiConverterSequenceUint64INSTANCE.Lower(indices), FfiConverterUint64INSTANCE.Lower(polySize), _uniffiStatus)
	}))
}

func ProveRaw(data []uint8, index uint64, polySize uint64) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_bls48581_fn_func_prove_raw(FfiConverterSequenceUint8INSTANCE.Lower(data), FfiConverterUint64INSTANCE.Lower(index), FfiConverterUint64INSTANCE.Lower(polySize), _uniffiStatus)
	}))
}

func VerifyMultiple(commitments [][]uint8, evaluations [][]uint8, indices []uint64, polySize uint64, multiCommitment []uint8, proof []uint8) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_bls48581_fn_func_verify_multiple(FfiConverterSequenceSequenceUint8INSTANCE.Lower(commitments), FfiConverterSequenceSequenceUint8INSTANCE.Lower(evaluations), FfiConverterSequenceUint64INSTANCE.Lower(indices), FfiConverterUint64INSTANCE.Lower(polySize), FfiConverterSequenceUint8INSTANCE.Lower(multiCommitment), FfiConverterSequenceUint8INSTANCE.Lower(proof), _uniffiStatus)
	}))
}

func VerifyRaw(data []uint8, commit []uint8, index uint64, proof []uint8, polySize uint64) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_bls48581_fn_func_verify_raw(FfiConverterSequenceUint8INSTANCE.Lower(data), FfiConverterSequenceUint8INSTANCE.Lower(commit), FfiConverterUint64INSTANCE.Lower(index), FfiConverterSequenceUint8INSTANCE.Lower(proof), FfiConverterUint64INSTANCE.Lower(polySize), _uniffiStatus)
	}))
}
