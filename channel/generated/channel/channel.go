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

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromExternal(b RustBufferI) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_channel_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_channel_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
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

func rustCallWithError[E any, U any](converter BufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
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
	bindingsContractVersion := 26
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_channel_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("channel: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_double_ratchet_decrypt()
		})
		if checksum != 13335 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_double_ratchet_decrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_double_ratchet_encrypt()
		})
		if checksum != 59209 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_double_ratchet_encrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_new_double_ratchet()
		})
		if checksum != 16925 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_new_double_ratchet: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_new_triple_ratchet()
		})
		if checksum != 20275 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_new_triple_ratchet: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_receiver_x3dh()
		})
		if checksum != 19343 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_receiver_x3dh: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_sender_x3dh()
		})
		if checksum != 41646 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_sender_x3dh: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_decrypt()
		})
		if checksum != 42324 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_decrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_encrypt()
		})
		if checksum != 61617 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_encrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_1()
		})
		if checksum != 42612 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_init_round_1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_2()
		})
		if checksum != 11875 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_init_round_2: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_3()
		})
		if checksum != 50331 {
			// If this happens try cleaning and rebuilding your project
			panic("channel: uniffi_channel_checksum_func_triple_ratchet_init_round_3: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_channel_checksum_func_triple_ratchet_init_round_4()
		})
		if checksum != 14779 {
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
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
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

type FfiConverterDoubleRatchetStateAndEnvelope struct{}

var FfiConverterDoubleRatchetStateAndEnvelopeINSTANCE = FfiConverterDoubleRatchetStateAndEnvelope{}

func (c FfiConverterDoubleRatchetStateAndEnvelope) Lift(rb RustBufferI) DoubleRatchetStateAndEnvelope {
	return LiftFromRustBuffer[DoubleRatchetStateAndEnvelope](c, rb)
}

func (c FfiConverterDoubleRatchetStateAndEnvelope) Read(reader io.Reader) DoubleRatchetStateAndEnvelope {
	return DoubleRatchetStateAndEnvelope{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterDoubleRatchetStateAndEnvelope) Lower(value DoubleRatchetStateAndEnvelope) C.RustBuffer {
	return LowerIntoRustBuffer[DoubleRatchetStateAndEnvelope](c, value)
}

func (c FfiConverterDoubleRatchetStateAndEnvelope) Write(writer io.Writer, value DoubleRatchetStateAndEnvelope) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterStringINSTANCE.Write(writer, value.Envelope)
}

type FfiDestroyerDoubleRatchetStateAndEnvelope struct{}

func (_ FfiDestroyerDoubleRatchetStateAndEnvelope) Destroy(value DoubleRatchetStateAndEnvelope) {
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

type FfiConverterDoubleRatchetStateAndMessage struct{}

var FfiConverterDoubleRatchetStateAndMessageINSTANCE = FfiConverterDoubleRatchetStateAndMessage{}

func (c FfiConverterDoubleRatchetStateAndMessage) Lift(rb RustBufferI) DoubleRatchetStateAndMessage {
	return LiftFromRustBuffer[DoubleRatchetStateAndMessage](c, rb)
}

func (c FfiConverterDoubleRatchetStateAndMessage) Read(reader io.Reader) DoubleRatchetStateAndMessage {
	return DoubleRatchetStateAndMessage{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterDoubleRatchetStateAndMessage) Lower(value DoubleRatchetStateAndMessage) C.RustBuffer {
	return LowerIntoRustBuffer[DoubleRatchetStateAndMessage](c, value)
}

func (c FfiConverterDoubleRatchetStateAndMessage) Write(writer io.Writer, value DoubleRatchetStateAndMessage) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Message)
}

type FfiDestroyerDoubleRatchetStateAndMessage struct{}

func (_ FfiDestroyerDoubleRatchetStateAndMessage) Destroy(value DoubleRatchetStateAndMessage) {
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

type FfiConverterTripleRatchetStateAndEnvelope struct{}

var FfiConverterTripleRatchetStateAndEnvelopeINSTANCE = FfiConverterTripleRatchetStateAndEnvelope{}

func (c FfiConverterTripleRatchetStateAndEnvelope) Lift(rb RustBufferI) TripleRatchetStateAndEnvelope {
	return LiftFromRustBuffer[TripleRatchetStateAndEnvelope](c, rb)
}

func (c FfiConverterTripleRatchetStateAndEnvelope) Read(reader io.Reader) TripleRatchetStateAndEnvelope {
	return TripleRatchetStateAndEnvelope{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTripleRatchetStateAndEnvelope) Lower(value TripleRatchetStateAndEnvelope) C.RustBuffer {
	return LowerIntoRustBuffer[TripleRatchetStateAndEnvelope](c, value)
}

func (c FfiConverterTripleRatchetStateAndEnvelope) Write(writer io.Writer, value TripleRatchetStateAndEnvelope) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterStringINSTANCE.Write(writer, value.Envelope)
}

type FfiDestroyerTripleRatchetStateAndEnvelope struct{}

func (_ FfiDestroyerTripleRatchetStateAndEnvelope) Destroy(value TripleRatchetStateAndEnvelope) {
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

type FfiConverterTripleRatchetStateAndMessage struct{}

var FfiConverterTripleRatchetStateAndMessageINSTANCE = FfiConverterTripleRatchetStateAndMessage{}

func (c FfiConverterTripleRatchetStateAndMessage) Lift(rb RustBufferI) TripleRatchetStateAndMessage {
	return LiftFromRustBuffer[TripleRatchetStateAndMessage](c, rb)
}

func (c FfiConverterTripleRatchetStateAndMessage) Read(reader io.Reader) TripleRatchetStateAndMessage {
	return TripleRatchetStateAndMessage{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTripleRatchetStateAndMessage) Lower(value TripleRatchetStateAndMessage) C.RustBuffer {
	return LowerIntoRustBuffer[TripleRatchetStateAndMessage](c, value)
}

func (c FfiConverterTripleRatchetStateAndMessage) Write(writer io.Writer, value TripleRatchetStateAndMessage) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Message)
}

type FfiDestroyerTripleRatchetStateAndMessage struct{}

func (_ FfiDestroyerTripleRatchetStateAndMessage) Destroy(value TripleRatchetStateAndMessage) {
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

type FfiConverterTripleRatchetStateAndMetadata struct{}

var FfiConverterTripleRatchetStateAndMetadataINSTANCE = FfiConverterTripleRatchetStateAndMetadata{}

func (c FfiConverterTripleRatchetStateAndMetadata) Lift(rb RustBufferI) TripleRatchetStateAndMetadata {
	return LiftFromRustBuffer[TripleRatchetStateAndMetadata](c, rb)
}

func (c FfiConverterTripleRatchetStateAndMetadata) Read(reader io.Reader) TripleRatchetStateAndMetadata {
	return TripleRatchetStateAndMetadata{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterMapStringStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTripleRatchetStateAndMetadata) Lower(value TripleRatchetStateAndMetadata) C.RustBuffer {
	return LowerIntoRustBuffer[TripleRatchetStateAndMetadata](c, value)
}

func (c FfiConverterTripleRatchetStateAndMetadata) Write(writer io.Writer, value TripleRatchetStateAndMetadata) {
	FfiConverterStringINSTANCE.Write(writer, value.RatchetState)
	FfiConverterMapStringStringINSTANCE.Write(writer, value.Metadata)
}

type FfiDestroyerTripleRatchetStateAndMetadata struct{}

func (_ FfiDestroyerTripleRatchetStateAndMetadata) Destroy(value TripleRatchetStateAndMetadata) {
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

func (c FfiConverterSequenceUint8) Lower(value []uint8) C.RustBuffer {
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

func (c FfiConverterSequenceSequenceUint8) Lower(value [][]uint8) C.RustBuffer {
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

func (c FfiConverterMapStringString) Lower(value map[string]string) C.RustBuffer {
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
	return FfiConverterDoubleRatchetStateAndMessageINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_double_ratchet_decrypt(FfiConverterDoubleRatchetStateAndEnvelopeINSTANCE.Lower(ratchetStateAndEnvelope), _uniffiStatus),
		}
	}))
}

func DoubleRatchetEncrypt(ratchetStateAndMessage DoubleRatchetStateAndMessage) DoubleRatchetStateAndEnvelope {
	return FfiConverterDoubleRatchetStateAndEnvelopeINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_double_ratchet_encrypt(FfiConverterDoubleRatchetStateAndMessageINSTANCE.Lower(ratchetStateAndMessage), _uniffiStatus),
		}
	}))
}

func NewDoubleRatchet(sessionKey []uint8, sendingHeaderKey []uint8, nextReceivingHeaderKey []uint8, isSender bool, sendingEphemeralPrivateKey []uint8, receivingEphemeralKey []uint8) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_new_double_ratchet(FfiConverterSequenceUint8INSTANCE.Lower(sessionKey), FfiConverterSequenceUint8INSTANCE.Lower(sendingHeaderKey), FfiConverterSequenceUint8INSTANCE.Lower(nextReceivingHeaderKey), FfiConverterBoolINSTANCE.Lower(isSender), FfiConverterSequenceUint8INSTANCE.Lower(sendingEphemeralPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingEphemeralKey), _uniffiStatus),
		}
	}))
}

func NewTripleRatchet(peers [][]uint8, peerKey []uint8, identityKey []uint8, signedPreKey []uint8, threshold uint64, asyncDkgRatchet bool) TripleRatchetStateAndMetadata {
	return FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_new_triple_ratchet(FfiConverterSequenceSequenceUint8INSTANCE.Lower(peers), FfiConverterSequenceUint8INSTANCE.Lower(peerKey), FfiConverterSequenceUint8INSTANCE.Lower(identityKey), FfiConverterSequenceUint8INSTANCE.Lower(signedPreKey), FfiConverterUint64INSTANCE.Lower(threshold), FfiConverterBoolINSTANCE.Lower(asyncDkgRatchet), _uniffiStatus),
		}
	}))
}

func ReceiverX3dh(sendingIdentityPrivateKey []uint8, sendingSignedPrivateKey []uint8, receivingIdentityKey []uint8, receivingEphemeralKey []uint8, sessionKeyLength uint64) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_receiver_x3dh(FfiConverterSequenceUint8INSTANCE.Lower(sendingIdentityPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(sendingSignedPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingIdentityKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingEphemeralKey), FfiConverterUint64INSTANCE.Lower(sessionKeyLength), _uniffiStatus),
		}
	}))
}

func SenderX3dh(sendingIdentityPrivateKey []uint8, sendingEphemeralPrivateKey []uint8, receivingIdentityKey []uint8, receivingSignedPreKey []uint8, sessionKeyLength uint64) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_sender_x3dh(FfiConverterSequenceUint8INSTANCE.Lower(sendingIdentityPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(sendingEphemeralPrivateKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingIdentityKey), FfiConverterSequenceUint8INSTANCE.Lower(receivingSignedPreKey), FfiConverterUint64INSTANCE.Lower(sessionKeyLength), _uniffiStatus),
		}
	}))
}

func TripleRatchetDecrypt(ratchetStateAndEnvelope TripleRatchetStateAndEnvelope) TripleRatchetStateAndMessage {
	return FfiConverterTripleRatchetStateAndMessageINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_triple_ratchet_decrypt(FfiConverterTripleRatchetStateAndEnvelopeINSTANCE.Lower(ratchetStateAndEnvelope), _uniffiStatus),
		}
	}))
}

func TripleRatchetEncrypt(ratchetStateAndMessage TripleRatchetStateAndMessage) TripleRatchetStateAndEnvelope {
	return FfiConverterTripleRatchetStateAndEnvelopeINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_triple_ratchet_encrypt(FfiConverterTripleRatchetStateAndMessageINSTANCE.Lower(ratchetStateAndMessage), _uniffiStatus),
		}
	}))
}

func TripleRatchetInitRound1(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_triple_ratchet_init_round_1(FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus),
		}
	}))
}

func TripleRatchetInitRound2(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_triple_ratchet_init_round_2(FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus),
		}
	}))
}

func TripleRatchetInitRound3(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_triple_ratchet_init_round_3(FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus),
		}
	}))
}

func TripleRatchetInitRound4(ratchetStateAndMetadata TripleRatchetStateAndMetadata) TripleRatchetStateAndMetadata {
	return FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_channel_fn_func_triple_ratchet_init_round_4(FfiConverterTripleRatchetStateAndMetadataINSTANCE.Lower(ratchetStateAndMetadata), _uniffiStatus),
		}
	}))
}
