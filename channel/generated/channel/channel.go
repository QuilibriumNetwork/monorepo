package channel

// #include <channel.h>
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
		C.ffi_channel_rustbuffer_free(cb, status)
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
		return C.ffi_channel_rustbuffer_from_bytes(foreign, status)
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
		return C.ffi_channel_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("channel: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_double_ratchet_decrypt(uniffiStatus)
		})
		if checksum != 57128 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_double_ratchet_decrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_double_ratchet_encrypt(uniffiStatus)
		})
		if checksum != 10167 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_double_ratchet_encrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_new_double_ratchet(uniffiStatus)
		})
		if checksum != 21249 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_new_double_ratchet: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_new_triple_ratchet(uniffiStatus)
		})
		if checksum != 11118 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_new_triple_ratchet: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_receiver_x3dh(uniffiStatus)
		})
		if checksum != 53802 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_receiver_x3dh: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_sender_x3dh(uniffiStatus)
		})
		if checksum != 2887 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_sender_x3dh: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_decrypt(uniffiStatus)
		})
		if checksum != 56417 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_decrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_encrypt(uniffiStatus)
		})
		if checksum != 63768 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_encrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_1(uniffiStatus)
		})
		if checksum != 48593 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_init_round_1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_2(uniffiStatus)
		})
		if checksum != 55359 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_init_round_2: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_3(uniffiStatus)
		})
		if checksum != 50330 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_init_round_3: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_4(uniffiStatus)
		})
		if checksum != 58513 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_init_round_4: UniFFI API checksum mismatch")
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

type DoubleRatchetStateAndEnvelope struct {
	RatchetState string
	Envelope     string
}

func (r *DoubleRatchetStateAndEnvelope) Destroy() {
	FfiDestroyerString{}.Destroy(r.RatchetState)
	FfiDestroyerString{}.Destroy(r.Envelope)
}

type FfiConverterTypeDoubleRatchetStateAndEnvelope struct{}

var FfiConverterTypeDoubleRatchetStateAndEnvelopeINSTANCE = FfiConverterTypeDoubleRatchetStateAndEnvelope{}

func (c FfiConverterTypeDoubleRatchetStateAndEnvelope) Lift(rb RustBufferI) DoubleRatchetStateAndEnvelope {
	return LiftFromRustBuffer[DoubleRatchetStateAndEnvelope](c, rb)
}

func (c FfiConverterTypeDoubleRatchetStateAndEnvelope) Read(reader io.Reader) DoubleRatchetStateAndEnvelope {
	return DoubleRatchetStateAndEnvelope{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeDoubleRatchetStateAndEnvelope) Lower(value DoubleRatchetStateAndEnvelope) RustBuffer {
	return LowerIntoRustBuffer[DoubleRatchetStateAndEnvelope](c, value)
}

func (c FfiConverterTypeDoubleRatchetStateAndEnvelope) Write(writer io.Writer, value DoubleRatchetStateAndEnvelope) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterStringINSTANCE.Write(writer, value.Envelope)
}

type FfiDestroyerTypeDoubleRatchetStateAndEnvelope struct{}

func (_ FfiDestroyerTypeDoubleRatchetStateAndEnvelope) Destroy(value DoubleRatchetStateAndEnvelope) {
	value.Destroy()
}

type DoubleRatchetStateAndMessage struct {
	RatchetState string
	Message      []uint8
}

func (r *DoubleRatchetStateAndMessage) Destroy() {
	FfiDestroyerString{}.Destroy(r.RatchetState)
	FfiDestroyerSequenceUint8{}.Destroy(r.Message)
}

type FfiConverterTypeDoubleRatchetStateAndMessage struct{}

var FfiConverterTypeDoubleRatchetStateAndMessageINSTANCE = FfiConverterTypeDoubleRatchetStateAndMessage{}

func (c FfiConverterTypeDoubleRatchetStateAndMessage) Lift(rb RustBufferI) DoubleRatchetStateAndMessage {
	return LiftFromRustBuffer[DoubleRatchetStateAndMessage](c, rb)
}

func (c FfiConverterTypeDoubleRatchetStateAndMessage) Read(reader io.Reader) DoubleRatchetStateAndMessage {
	return DoubleRatchetStateAndMessage{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeDoubleRatchetStateAndMessage) Lower(value DoubleRatchetStateAndMessage) RustBuffer {
	return LowerIntoRustBuffer[DoubleRatchetStateAndMessage](c, value)
}

func (c FfiConverterTypeDoubleRatchetStateAndMessage) Write(writer io.Writer, value DoubleRatchetStateAndMessage) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Message)
}

type FfiDestroyerTypeDoubleRatchetStateAndMessage struct{}

func (_ FfiDestroyerTypeDoubleRatchetStateAndMessage) Destroy(value DoubleRatchetStateAndMessage) {
	value.Destroy()
}

type TripleRatchetStateAndEnvelope struct {
	RatchetState string
	Envelope     string
}

func (r *TripleRatchetStateAndEnvelope) Destroy() {
	FfiDestroyerString{}.Destroy(r.RatchetState)
	FfiDestroyerString{}.Destroy(r.Envelope)
}

type FfiConverterTypeTripleRatchetStateAndEnvelope struct{}

var FfiConverterTypeTripleRatchetStateAndEnvelopeINSTANCE = FfiConverterTypeTripleRatchetStateAndEnvelope{}

func (c FfiConverterTypeTripleRatchetStateAndEnvelope) Lift(rb RustBufferI) TripleRatchetStateAndEnvelope {
	return LiftFromRustBuffer[TripleRatchetStateAndEnvelope](c, rb)
}

func (c FfiConverterTypeTripleRatchetStateAndEnvelope) Read(reader io.Reader) TripleRatchetStateAndEnvelope {
	return TripleRatchetStateAndEnvelope{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeTripleRatchetStateAndEnvelope) Lower(value TripleRatchetStateAndEnvelope) RustBuffer {
	return LowerIntoRustBuffer[TripleRatchetStateAndEnvelope](c, value)
}

func (c FfiConverterTypeTripleRatchetStateAndEnvelope) Write(writer io.Writer, value TripleRatchetStateAndEnvelope) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterStringINSTANCE.Write(writer, value.Envelope)
}

type FfiDestroyerTypeTripleRatchetStateAndEnvelope struct{}

func (_ FfiDestroyerTypeTripleRatchetStateAndEnvelope) Destroy(value TripleRatchetStateAndEnvelope) {
	value.Destroy()
}

type TripleRatchetStateAndMessage struct {
	RatchetState string
	Message      []uint8
}

func (r *TripleRatchetStateAndMessage) Destroy() {
	FfiDestroyerString{}.Destroy(r.RatchetState)
	FfiDestroyerSequenceUint8{}.Destroy(r.Message)
}

type FfiConverterTypeTripleRatchetStateAndMessage struct{}

var FfiConverterTypeTripleRatchetStateAndMessageINSTANCE = FfiConverterTypeTripleRatchetStateAndMessage{}

func (c FfiConverterTypeTripleRatchetStateAndMessage) Lift(rb RustBufferI) TripleRatchetStateAndMessage {
	return LiftFromRustBuffer[TripleRatchetStateAndMessage](c, rb)
}

func (c FfiConverterTypeTripleRatchetStateAndMessage) Read(reader io.Reader) TripleRatchetStateAndMessage {
	return TripleRatchetStateAndMessage{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeTripleRatchetStateAndMessage) Lower(value TripleRatchetStateAndMessage) RustBuffer {
	return LowerIntoRustBuffer[TripleRatchetStateAndMessage](c, value)
}

func (c FfiConverterTypeTripleRatchetStateAndMessage) Write(writer io.Writer, value TripleRatchetStateAndMessage) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Message)
}

type FfiDestroyerTypeTripleRatchetStateAndMessage struct{}

func (_ FfiDestroyerTypeTripleRatchetStateAndMessage) Destroy(value TripleRatchetStateAndMessage) {
	value.Destroy()
}

type TripleRatchetStateAndMetadata struct {
	RatchetState string
	Metadata     map[string]string
}

func (r *TripleRatchetStateAndMetadata) Destroy() {
	FfiDestroyerString{}.Destroy(r.RatchetState)
	FfiDestroyerMapStringString{}.Destroy(r.Metadata)
}

type FfiConverterTypeTripleRatchetStateAndMetadata struct{}

var FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE = FfiConverterTypeTripleRatchetStateAndMetadata{}

func (c FfiConverterTypeTripleRatchetStateAndMetadata) Lift(rb RustBufferI) TripleRatchetStateAndMetadata {
	return LiftFromRustBuffer[TripleRatchetStateAndMetadata](c, rb)
}

func (c FfiConverterTypeTripleRatchetStateAndMetadata) Read(reader io.Reader) TripleRatchetStateAndMetadata {
	return TripleRatchetStateAndMetadata{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterMapStringStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeTripleRatchetStateAndMetadata) Lower(value TripleRatchetStateAndMetadata) RustBuffer {
	return LowerIntoRustBuffer[TripleRatchetStateAndMetadata](c, value)
}

func (c FfiConverterTypeTripleRatchetStateAndMetadata) Write(writer io.Writer, value TripleRatchetStateAndMetadata) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterMapStringStringINSTANCE.Write(writer, value.Metadata)
}

type FfiDestroyerTypeTripleRatchetStateAndMetadata struct{}

func (_ FfiDestroyerTypeTripleRatchetStateAndMetadata) Destroy(value TripleRatchetStateAndMetadata) {
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

type FfiConverterMapStringString struct{}

var FfiConverterMapStringStringINSTANCE = FfiConverterMapStringString{}

func (c FfiConverterMapStringString) Lift(rb RustBufferI) map[string]string {
	return LiftFromRustBuffer[map[string]string](c, rb)
}

func (_ FfiConverterMapStringString) Read(reader io.Reader) map[string]string {
	result := make(map[string]string)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterStringINSTANCE.Read(reader)
		value := FfiConverterStringINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapStringString) Lower(value map[string]string) RustBuffer {
	return LowerIntoRustBuffer[map[string]string](c, value)
}

func (_ FfiConverterMapStringString) Write(writer io.Writer, mapValue map[string]string) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[string]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterStringINSTANCE.Write(writer, key)
		FfiConverterStringINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapStringString struct{}

func (_ FfiDestroyerMapStringString) Destroy(mapValue map[string]string) {
	for key, value := range mapValue {
		FfiDestroyerString{}.Destroy(key)
		FfiDestroyerString{}.Destroy(value)
	}
}

func DoubleRatchetDecrypt(ratchetStateAndEnvelope DoubleRatchetStateAndEnvelope) DoubleRatchetStateAndMessage {
	return FfiConverterTypeDoubleRatchetStateAndMessageINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_double_ratchet_decrypt(FfiConverterTypeDoubleRatchetStateAndEnvelopeINSTANCE.Lower(ratchetStateAndEnvelope), _uniffiStatus)
	}))
}

func DoubleRatchetEncrypt(ratchetStateAndMessage DoubleRatchetStateAndMessage) DoubleRatchetStateAndEnvelope {
	return FfiConverterTypeDoubleRatchetStateAndEnvelopeINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_double_ratchet_encrypt(FfiConverterTypeDoubleRatchetStateAndMessageINSTANCE.Lower(ratchetStateAndMessage), _uniffiStatus)
	}))
}

func NewDoubleRatchet(sessionKey []uint8, sendingHeaderKey []uint8, nextReceivingHeaderKey []uint8, isSender bool, sendingEphemeralPrivateKey []uint8, receivingEphemeralKey []uint8) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_new_double_ratchet(FfiConverterSequenceUint8INSTANCE.Lower(sessionKey), FfiConverterSequenceUint8INSTANCE.Lower(sendingHeaderKey), FfiConverterSequenceUint8INSTANCE.Lower(nextReceivingHeaderKey), FfiConverterBoolINSTANCE.Lower(isSender), FfiConverterSequenceUint8INSTANCE.Lower(sendingEphemeralPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingEphemeralKey), _uniffiStatus)
	}))
}

func NewTripleRatchet(peers [][]uint8, peerKey []uint8, identityKey []uint8, signedPreKey []uint8, threshold uint64, asyncDkgRatchet bool) TripleRatchetStateAndMetadata {
	return FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_new_triple_ratchet(FfiConverterSequenceSequenceUint8INSTANCE.Lower(peers), FfiConverterSequenceUint8INSTANCE.Lower(peerKey), FfiConverterSequenceUint8INSTANCE.Lower(identityKey), FfiConverterSequenceUint8INSTANCE.Lower(signedPreKey), FfiConverterUint64INSTANCE.Lower(threshold), FfiConverterBoolINSTANCE.Lower(asyncDkgRatchet), _uniffiStatus)
	}))
}

func ReceiverX3dh(sendingIdentityPrivateKey []uint8, sendingSignedPrivateKey []uint8, receivingIdentityKey []uint8, receivingEphemeralKey []uint8, sessionKeyLength uint64) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_receiver_x3dh(FfiConverterSequenceUint8INSTANCE.Lower(sendingIdentityPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(sendingSignedPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingIdentityKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingEphemeralKey), FfiConverterUint64INSTANCE.Lower(sessionKeyLength), _uniffiStatus)
	}))
}

func SenderX3dh(sendingIdentityPrivateKey []uint8, sendingEphemeralPrivateKey []uint8, receivingIdentityKey []uint8, receivingSignedPreKey []uint8, sessionKeyLength uint64) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_sender_x3dh(FfiConverterSequenceUint8INSTANCE.Lower(sendingIdentityPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(sendingEphemeralPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingIdentityKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingSignedPreKey), FfiConverterUint64INSTANCE.Lower(sessionKeyLength), _uniffiStatus)
	}))
}

func TripleRatchetDecrypt(ratchetStateAndEnvelope TripleRatchetStateAndEnvelope) TripleRatchetStateAndMessage {
	return FfiConverterTypeTripleRatchetStateAndMessageINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_triple_ratchet_decrypt(FfiConverterTypeTripleRatchetStateAndEnvelopeINSTANCE.Lower(ratchetStateAndEnvelope), _uniffiStatus)
	}))
}

func TripleRatchetEncrypt(ratchetStateAndMessage TripleRatchetStateAndMessage) TripleRatchetStateAndEnvelope {
	return FfiConverterTypeTripleRatchetStateAndEnvelopeINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_triple_ratchet_encrypt(FfiConverterTypeTripleRatchetStateAndMessageINSTANCE.Lower(ratchetStateAndMessage), _uniffiStatus)
	}))
}

func TripleRatchetInitRound1(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_triple_ratchet_init_round_1(FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus)
	}))
}

func TripleRatchetInitRound2(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_triple_ratchet_init_round_2(FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus)
	}))
}

func TripleRatchetInitRound3(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_triple_ratchet_init_round_3(FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus)
	}))
}

func TripleRatchetInitRound4(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_channel_fn_func_triple_ratchet_init_round_4(FfiConverterTypeTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus)
	}))
}
