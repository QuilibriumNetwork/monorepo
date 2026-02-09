package dkls23_ffi

// #include <dkls23_ffi.h>
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
		C.ffi_dkls23_ffi_rustbuffer_free(cb.inner, status)
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
		return C.ffi_dkls23_ffi_rustbuffer_from_bytes(foreign, status)
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
		return C.ffi_dkls23_ffi_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("dkls23_ffi: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_derive_child_share()
		})
		if checksum != 53456 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_derive_child_share: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_dkg_finalize()
		})
		if checksum != 47857 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_dkg_finalize: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_dkg_init()
		})
		if checksum != 47402 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_dkg_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_dkg_init_with_session_id()
		})
		if checksum != 2589 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_dkg_init_with_session_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_dkg_round1()
		})
		if checksum != 19607 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_dkg_round1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_dkg_round2()
		})
		if checksum != 22370 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_dkg_round2: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_dkg_round3()
		})
		if checksum != 41581 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_dkg_round3: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_get_public_key()
		})
		if checksum != 1292 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_get_public_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_init()
		})
		if checksum != 48233 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_refresh_finalize()
		})
		if checksum != 25302 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_refresh_finalize: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_refresh_init()
		})
		if checksum != 28108 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_refresh_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_refresh_init_with_refresh_id()
		})
		if checksum != 59540 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_refresh_init_with_refresh_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_refresh_round1()
		})
		if checksum != 60032 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_refresh_round1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_refresh_round2()
		})
		if checksum != 433 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_refresh_round2: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_refresh_round3()
		})
		if checksum != 34814 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_refresh_round3: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_rekey_from_secret()
		})
		if checksum != 38937 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_rekey_from_secret: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_resize_init()
		})
		if checksum != 31082 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_resize_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_resize_round1()
		})
		if checksum != 55154 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_resize_round1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_resize_round2()
		})
		if checksum != 33018 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_resize_round2: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_sign_finalize()
		})
		if checksum != 20629 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_sign_finalize: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_sign_init()
		})
		if checksum != 10463 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_sign_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_sign_init_with_sign_id()
		})
		if checksum != 4578 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_sign_init_with_sign_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_sign_round1()
		})
		if checksum != 41213 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_sign_round1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_sign_round2()
		})
		if checksum != 38058 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_sign_round2: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_sign_round3()
		})
		if checksum != 24081 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_sign_round3: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_dkls23_ffi_checksum_func_validate_key_share()
		})
		if checksum != 30314 {
			// If this happens try cleaning and rebuilding your project
			panic("dkls23_ffi: uniffi_dkls23_ffi_checksum_func_validate_key_share: UniFFI API checksum mismatch")
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

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

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

type DeriveResult struct {
	DerivedKeyShare  []uint8
	DerivedPublicKey []uint8
	Success          bool
	ErrorMessage     *string
}

func (r *DeriveResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.DerivedKeyShare)
	FfiDestroyerSequenceUint8{}.Destroy(r.DerivedPublicKey)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterDeriveResult struct{}

var FfiConverterDeriveResultINSTANCE = FfiConverterDeriveResult{}

func (c FfiConverterDeriveResult) Lift(rb RustBufferI) DeriveResult {
	return LiftFromRustBuffer[DeriveResult](c, rb)
}

func (c FfiConverterDeriveResult) Read(reader io.Reader) DeriveResult {
	return DeriveResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterDeriveResult) Lower(value DeriveResult) C.RustBuffer {
	return LowerIntoRustBuffer[DeriveResult](c, value)
}

func (c FfiConverterDeriveResult) Write(writer io.Writer, value DeriveResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.DerivedKeyShare)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.DerivedPublicKey)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerDeriveResult struct{}

func (_ FfiDestroyerDeriveResult) Destroy(value DeriveResult) {
	value.Destroy()
}

type DkgFinalResult struct {
	KeyShare     []uint8
	PublicKey    []uint8
	PartyId      uint32
	Threshold    uint32
	TotalParties uint32
	Success      bool
	ErrorMessage *string
}

func (r *DkgFinalResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.KeyShare)
	FfiDestroyerSequenceUint8{}.Destroy(r.PublicKey)
	FfiDestroyerUint32{}.Destroy(r.PartyId)
	FfiDestroyerUint32{}.Destroy(r.Threshold)
	FfiDestroyerUint32{}.Destroy(r.TotalParties)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterDkgFinalResult struct{}

var FfiConverterDkgFinalResultINSTANCE = FfiConverterDkgFinalResult{}

func (c FfiConverterDkgFinalResult) Lift(rb RustBufferI) DkgFinalResult {
	return LiftFromRustBuffer[DkgFinalResult](c, rb)
}

func (c FfiConverterDkgFinalResult) Read(reader io.Reader) DkgFinalResult {
	return DkgFinalResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterDkgFinalResult) Lower(value DkgFinalResult) C.RustBuffer {
	return LowerIntoRustBuffer[DkgFinalResult](c, value)
}

func (c FfiConverterDkgFinalResult) Write(writer io.Writer, value DkgFinalResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.KeyShare)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.PublicKey)
	FfiConverterUint32INSTANCE.Write(writer, value.PartyId)
	FfiConverterUint32INSTANCE.Write(writer, value.Threshold)
	FfiConverterUint32INSTANCE.Write(writer, value.TotalParties)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerDkgFinalResult struct{}

func (_ FfiDestroyerDkgFinalResult) Destroy(value DkgFinalResult) {
	value.Destroy()
}

type DkgInitResult struct {
	SessionState []uint8
	Success      bool
	ErrorMessage *string
}

func (r *DkgInitResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterDkgInitResult struct{}

var FfiConverterDkgInitResultINSTANCE = FfiConverterDkgInitResult{}

func (c FfiConverterDkgInitResult) Lift(rb RustBufferI) DkgInitResult {
	return LiftFromRustBuffer[DkgInitResult](c, rb)
}

func (c FfiConverterDkgInitResult) Read(reader io.Reader) DkgInitResult {
	return DkgInitResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterDkgInitResult) Lower(value DkgInitResult) C.RustBuffer {
	return LowerIntoRustBuffer[DkgInitResult](c, value)
}

func (c FfiConverterDkgInitResult) Write(writer io.Writer, value DkgInitResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerDkgInitResult struct{}

func (_ FfiDestroyerDkgInitResult) Destroy(value DkgInitResult) {
	value.Destroy()
}

type DkgRoundResult struct {
	SessionState   []uint8
	MessagesToSend []PartyMessage
	IsComplete     bool
	Success        bool
	ErrorMessage   *string
}

func (r *DkgRoundResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerSequencePartyMessage{}.Destroy(r.MessagesToSend)
	FfiDestroyerBool{}.Destroy(r.IsComplete)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterDkgRoundResult struct{}

var FfiConverterDkgRoundResultINSTANCE = FfiConverterDkgRoundResult{}

func (c FfiConverterDkgRoundResult) Lift(rb RustBufferI) DkgRoundResult {
	return LiftFromRustBuffer[DkgRoundResult](c, rb)
}

func (c FfiConverterDkgRoundResult) Read(reader io.Reader) DkgRoundResult {
	return DkgRoundResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequencePartyMessageINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterDkgRoundResult) Lower(value DkgRoundResult) C.RustBuffer {
	return LowerIntoRustBuffer[DkgRoundResult](c, value)
}

func (c FfiConverterDkgRoundResult) Write(writer io.Writer, value DkgRoundResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterSequencePartyMessageINSTANCE.Write(writer, value.MessagesToSend)
	FfiConverterBoolINSTANCE.Write(writer, value.IsComplete)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerDkgRoundResult struct{}

func (_ FfiDestroyerDkgRoundResult) Destroy(value DkgRoundResult) {
	value.Destroy()
}

type PartyMessage struct {
	FromParty uint32
	ToParty   uint32
	Data      []uint8
}

func (r *PartyMessage) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.FromParty)
	FfiDestroyerUint32{}.Destroy(r.ToParty)
	FfiDestroyerSequenceUint8{}.Destroy(r.Data)
}

type FfiConverterPartyMessage struct{}

var FfiConverterPartyMessageINSTANCE = FfiConverterPartyMessage{}

func (c FfiConverterPartyMessage) Lift(rb RustBufferI) PartyMessage {
	return LiftFromRustBuffer[PartyMessage](c, rb)
}

func (c FfiConverterPartyMessage) Read(reader io.Reader) PartyMessage {
	return PartyMessage{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterPartyMessage) Lower(value PartyMessage) C.RustBuffer {
	return LowerIntoRustBuffer[PartyMessage](c, value)
}

func (c FfiConverterPartyMessage) Write(writer io.Writer, value PartyMessage) {
	FfiConverterUint32INSTANCE.Write(writer, value.FromParty)
	FfiConverterUint32INSTANCE.Write(writer, value.ToParty)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Data)
}

type FfiDestroyerPartyMessage struct{}

func (_ FfiDestroyerPartyMessage) Destroy(value PartyMessage) {
	value.Destroy()
}

type RefreshFinalResult struct {
	NewKeyShare  []uint8
	Generation   uint32
	Success      bool
	ErrorMessage *string
}

func (r *RefreshFinalResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.NewKeyShare)
	FfiDestroyerUint32{}.Destroy(r.Generation)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterRefreshFinalResult struct{}

var FfiConverterRefreshFinalResultINSTANCE = FfiConverterRefreshFinalResult{}

func (c FfiConverterRefreshFinalResult) Lift(rb RustBufferI) RefreshFinalResult {
	return LiftFromRustBuffer[RefreshFinalResult](c, rb)
}

func (c FfiConverterRefreshFinalResult) Read(reader io.Reader) RefreshFinalResult {
	return RefreshFinalResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterRefreshFinalResult) Lower(value RefreshFinalResult) C.RustBuffer {
	return LowerIntoRustBuffer[RefreshFinalResult](c, value)
}

func (c FfiConverterRefreshFinalResult) Write(writer io.Writer, value RefreshFinalResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.NewKeyShare)
	FfiConverterUint32INSTANCE.Write(writer, value.Generation)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerRefreshFinalResult struct{}

func (_ FfiDestroyerRefreshFinalResult) Destroy(value RefreshFinalResult) {
	value.Destroy()
}

type RefreshInitResult struct {
	SessionState []uint8
	Success      bool
	ErrorMessage *string
}

func (r *RefreshInitResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterRefreshInitResult struct{}

var FfiConverterRefreshInitResultINSTANCE = FfiConverterRefreshInitResult{}

func (c FfiConverterRefreshInitResult) Lift(rb RustBufferI) RefreshInitResult {
	return LiftFromRustBuffer[RefreshInitResult](c, rb)
}

func (c FfiConverterRefreshInitResult) Read(reader io.Reader) RefreshInitResult {
	return RefreshInitResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterRefreshInitResult) Lower(value RefreshInitResult) C.RustBuffer {
	return LowerIntoRustBuffer[RefreshInitResult](c, value)
}

func (c FfiConverterRefreshInitResult) Write(writer io.Writer, value RefreshInitResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerRefreshInitResult struct{}

func (_ FfiDestroyerRefreshInitResult) Destroy(value RefreshInitResult) {
	value.Destroy()
}

type RefreshRoundResult struct {
	SessionState   []uint8
	MessagesToSend []PartyMessage
	IsComplete     bool
	Success        bool
	ErrorMessage   *string
}

func (r *RefreshRoundResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerSequencePartyMessage{}.Destroy(r.MessagesToSend)
	FfiDestroyerBool{}.Destroy(r.IsComplete)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterRefreshRoundResult struct{}

var FfiConverterRefreshRoundResultINSTANCE = FfiConverterRefreshRoundResult{}

func (c FfiConverterRefreshRoundResult) Lift(rb RustBufferI) RefreshRoundResult {
	return LiftFromRustBuffer[RefreshRoundResult](c, rb)
}

func (c FfiConverterRefreshRoundResult) Read(reader io.Reader) RefreshRoundResult {
	return RefreshRoundResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequencePartyMessageINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterRefreshRoundResult) Lower(value RefreshRoundResult) C.RustBuffer {
	return LowerIntoRustBuffer[RefreshRoundResult](c, value)
}

func (c FfiConverterRefreshRoundResult) Write(writer io.Writer, value RefreshRoundResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterSequencePartyMessageINSTANCE.Write(writer, value.MessagesToSend)
	FfiConverterBoolINSTANCE.Write(writer, value.IsComplete)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerRefreshRoundResult struct{}

func (_ FfiDestroyerRefreshRoundResult) Destroy(value RefreshRoundResult) {
	value.Destroy()
}

type RekeyResult struct {
	KeyShares    [][]uint8
	PublicKey    []uint8
	Success      bool
	ErrorMessage *string
}

func (r *RekeyResult) Destroy() {
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.KeyShares)
	FfiDestroyerSequenceUint8{}.Destroy(r.PublicKey)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterRekeyResult struct{}

var FfiConverterRekeyResultINSTANCE = FfiConverterRekeyResult{}

func (c FfiConverterRekeyResult) Lift(rb RustBufferI) RekeyResult {
	return LiftFromRustBuffer[RekeyResult](c, rb)
}

func (c FfiConverterRekeyResult) Read(reader io.Reader) RekeyResult {
	return RekeyResult{
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterRekeyResult) Lower(value RekeyResult) C.RustBuffer {
	return LowerIntoRustBuffer[RekeyResult](c, value)
}

func (c FfiConverterRekeyResult) Write(writer io.Writer, value RekeyResult) {
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.KeyShares)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.PublicKey)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerRekeyResult struct{}

func (_ FfiDestroyerRekeyResult) Destroy(value RekeyResult) {
	value.Destroy()
}

type ResizeFinalResult struct {
	NewKeyShare     []uint8
	NewThreshold    uint32
	NewTotalParties uint32
	Success         bool
	ErrorMessage    *string
}

func (r *ResizeFinalResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.NewKeyShare)
	FfiDestroyerUint32{}.Destroy(r.NewThreshold)
	FfiDestroyerUint32{}.Destroy(r.NewTotalParties)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterResizeFinalResult struct{}

var FfiConverterResizeFinalResultINSTANCE = FfiConverterResizeFinalResult{}

func (c FfiConverterResizeFinalResult) Lift(rb RustBufferI) ResizeFinalResult {
	return LiftFromRustBuffer[ResizeFinalResult](c, rb)
}

func (c FfiConverterResizeFinalResult) Read(reader io.Reader) ResizeFinalResult {
	return ResizeFinalResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterResizeFinalResult) Lower(value ResizeFinalResult) C.RustBuffer {
	return LowerIntoRustBuffer[ResizeFinalResult](c, value)
}

func (c FfiConverterResizeFinalResult) Write(writer io.Writer, value ResizeFinalResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.NewKeyShare)
	FfiConverterUint32INSTANCE.Write(writer, value.NewThreshold)
	FfiConverterUint32INSTANCE.Write(writer, value.NewTotalParties)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerResizeFinalResult struct{}

func (_ FfiDestroyerResizeFinalResult) Destroy(value ResizeFinalResult) {
	value.Destroy()
}

type ResizeInitResult struct {
	SessionState []uint8
	Success      bool
	ErrorMessage *string
}

func (r *ResizeInitResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterResizeInitResult struct{}

var FfiConverterResizeInitResultINSTANCE = FfiConverterResizeInitResult{}

func (c FfiConverterResizeInitResult) Lift(rb RustBufferI) ResizeInitResult {
	return LiftFromRustBuffer[ResizeInitResult](c, rb)
}

func (c FfiConverterResizeInitResult) Read(reader io.Reader) ResizeInitResult {
	return ResizeInitResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterResizeInitResult) Lower(value ResizeInitResult) C.RustBuffer {
	return LowerIntoRustBuffer[ResizeInitResult](c, value)
}

func (c FfiConverterResizeInitResult) Write(writer io.Writer, value ResizeInitResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerResizeInitResult struct{}

func (_ FfiDestroyerResizeInitResult) Destroy(value ResizeInitResult) {
	value.Destroy()
}

type ResizeRoundResult struct {
	SessionState   []uint8
	MessagesToSend []PartyMessage
	IsComplete     bool
	Success        bool
	ErrorMessage   *string
}

func (r *ResizeRoundResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerSequencePartyMessage{}.Destroy(r.MessagesToSend)
	FfiDestroyerBool{}.Destroy(r.IsComplete)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterResizeRoundResult struct{}

var FfiConverterResizeRoundResultINSTANCE = FfiConverterResizeRoundResult{}

func (c FfiConverterResizeRoundResult) Lift(rb RustBufferI) ResizeRoundResult {
	return LiftFromRustBuffer[ResizeRoundResult](c, rb)
}

func (c FfiConverterResizeRoundResult) Read(reader io.Reader) ResizeRoundResult {
	return ResizeRoundResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequencePartyMessageINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterResizeRoundResult) Lower(value ResizeRoundResult) C.RustBuffer {
	return LowerIntoRustBuffer[ResizeRoundResult](c, value)
}

func (c FfiConverterResizeRoundResult) Write(writer io.Writer, value ResizeRoundResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterSequencePartyMessageINSTANCE.Write(writer, value.MessagesToSend)
	FfiConverterBoolINSTANCE.Write(writer, value.IsComplete)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerResizeRoundResult struct{}

func (_ FfiDestroyerResizeRoundResult) Destroy(value ResizeRoundResult) {
	value.Destroy()
}

type SignFinalResult struct {
	Signature    []uint8
	Success      bool
	ErrorMessage *string
}

func (r *SignFinalResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.Signature)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterSignFinalResult struct{}

var FfiConverterSignFinalResultINSTANCE = FfiConverterSignFinalResult{}

func (c FfiConverterSignFinalResult) Lift(rb RustBufferI) SignFinalResult {
	return LiftFromRustBuffer[SignFinalResult](c, rb)
}

func (c FfiConverterSignFinalResult) Read(reader io.Reader) SignFinalResult {
	return SignFinalResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterSignFinalResult) Lower(value SignFinalResult) C.RustBuffer {
	return LowerIntoRustBuffer[SignFinalResult](c, value)
}

func (c FfiConverterSignFinalResult) Write(writer io.Writer, value SignFinalResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Signature)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerSignFinalResult struct{}

func (_ FfiDestroyerSignFinalResult) Destroy(value SignFinalResult) {
	value.Destroy()
}

type SignInitResult struct {
	SessionState []uint8
	Success      bool
	ErrorMessage *string
}

func (r *SignInitResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterSignInitResult struct{}

var FfiConverterSignInitResultINSTANCE = FfiConverterSignInitResult{}

func (c FfiConverterSignInitResult) Lift(rb RustBufferI) SignInitResult {
	return LiftFromRustBuffer[SignInitResult](c, rb)
}

func (c FfiConverterSignInitResult) Read(reader io.Reader) SignInitResult {
	return SignInitResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterSignInitResult) Lower(value SignInitResult) C.RustBuffer {
	return LowerIntoRustBuffer[SignInitResult](c, value)
}

func (c FfiConverterSignInitResult) Write(writer io.Writer, value SignInitResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerSignInitResult struct{}

func (_ FfiDestroyerSignInitResult) Destroy(value SignInitResult) {
	value.Destroy()
}

type SignRoundResult struct {
	SessionState   []uint8
	MessagesToSend []PartyMessage
	IsComplete     bool
	Success        bool
	ErrorMessage   *string
}

func (r *SignRoundResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.SessionState)
	FfiDestroyerSequencePartyMessage{}.Destroy(r.MessagesToSend)
	FfiDestroyerBool{}.Destroy(r.IsComplete)
	FfiDestroyerBool{}.Destroy(r.Success)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorMessage)
}

type FfiConverterSignRoundResult struct{}

var FfiConverterSignRoundResultINSTANCE = FfiConverterSignRoundResult{}

func (c FfiConverterSignRoundResult) Lift(rb RustBufferI) SignRoundResult {
	return LiftFromRustBuffer[SignRoundResult](c, rb)
}

func (c FfiConverterSignRoundResult) Read(reader io.Reader) SignRoundResult {
	return SignRoundResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequencePartyMessageINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterSignRoundResult) Lower(value SignRoundResult) C.RustBuffer {
	return LowerIntoRustBuffer[SignRoundResult](c, value)
}

func (c FfiConverterSignRoundResult) Write(writer io.Writer, value SignRoundResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SessionState)
	FfiConverterSequencePartyMessageINSTANCE.Write(writer, value.MessagesToSend)
	FfiConverterBoolINSTANCE.Write(writer, value.IsComplete)
	FfiConverterBoolINSTANCE.Write(writer, value.Success)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorMessage)
}

type FfiDestroyerSignRoundResult struct{}

func (_ FfiDestroyerSignRoundResult) Destroy(value SignRoundResult) {
	value.Destroy()
}

type EllipticCurve uint

const (
	EllipticCurveSecp256k1 EllipticCurve = 1
	EllipticCurveP256      EllipticCurve = 2
)

type FfiConverterEllipticCurve struct{}

var FfiConverterEllipticCurveINSTANCE = FfiConverterEllipticCurve{}

func (c FfiConverterEllipticCurve) Lift(rb RustBufferI) EllipticCurve {
	return LiftFromRustBuffer[EllipticCurve](c, rb)
}

func (c FfiConverterEllipticCurve) Lower(value EllipticCurve) C.RustBuffer {
	return LowerIntoRustBuffer[EllipticCurve](c, value)
}
func (FfiConverterEllipticCurve) Read(reader io.Reader) EllipticCurve {
	id := readInt32(reader)
	return EllipticCurve(id)
}

func (FfiConverterEllipticCurve) Write(writer io.Writer, value EllipticCurve) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerEllipticCurve struct{}

func (_ FfiDestroyerEllipticCurve) Destroy(value EllipticCurve) {
}

type FfiConverterOptionalString struct{}

var FfiConverterOptionalStringINSTANCE = FfiConverterOptionalString{}

func (c FfiConverterOptionalString) Lift(rb RustBufferI) *string {
	return LiftFromRustBuffer[*string](c, rb)
}

func (_ FfiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalString) Lower(value *string) C.RustBuffer {
	return LowerIntoRustBuffer[*string](c, value)
}

func (_ FfiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalString struct{}

func (_ FfiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		FfiDestroyerString{}.Destroy(*value)
	}
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

type FfiConverterSequenceUint32 struct{}

var FfiConverterSequenceUint32INSTANCE = FfiConverterSequenceUint32{}

func (c FfiConverterSequenceUint32) Lift(rb RustBufferI) []uint32 {
	return LiftFromRustBuffer[[]uint32](c, rb)
}

func (c FfiConverterSequenceUint32) Read(reader io.Reader) []uint32 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint32, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint32INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint32) Lower(value []uint32) C.RustBuffer {
	return LowerIntoRustBuffer[[]uint32](c, value)
}

func (c FfiConverterSequenceUint32) Write(writer io.Writer, value []uint32) {
	if len(value) > math.MaxInt32 {
		panic("[]uint32 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint32INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint32 struct{}

func (FfiDestroyerSequenceUint32) Destroy(sequence []uint32) {
	for _, value := range sequence {
		FfiDestroyerUint32{}.Destroy(value)
	}
}

type FfiConverterSequencePartyMessage struct{}

var FfiConverterSequencePartyMessageINSTANCE = FfiConverterSequencePartyMessage{}

func (c FfiConverterSequencePartyMessage) Lift(rb RustBufferI) []PartyMessage {
	return LiftFromRustBuffer[[]PartyMessage](c, rb)
}

func (c FfiConverterSequencePartyMessage) Read(reader io.Reader) []PartyMessage {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]PartyMessage, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterPartyMessageINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequencePartyMessage) Lower(value []PartyMessage) C.RustBuffer {
	return LowerIntoRustBuffer[[]PartyMessage](c, value)
}

func (c FfiConverterSequencePartyMessage) Write(writer io.Writer, value []PartyMessage) {
	if len(value) > math.MaxInt32 {
		panic("[]PartyMessage is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterPartyMessageINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequencePartyMessage struct{}

func (FfiDestroyerSequencePartyMessage) Destroy(sequence []PartyMessage) {
	for _, value := range sequence {
		FfiDestroyerPartyMessage{}.Destroy(value)
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

func DeriveChildShare(keyShare []uint8, derivationPath []uint32) DeriveResult {
	return FfiConverterDeriveResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_derive_child_share(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), FfiConverterSequenceUint32INSTANCE.Lower(derivationPath), _uniffiStatus),
		}
	}))
}

func DkgFinalize(sessionState []uint8, receivedMessages []PartyMessage) DkgFinalResult {
	return FfiConverterDkgFinalResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_dkg_finalize(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func DkgInit(partyId uint32, threshold uint32, totalParties uint32, curve EllipticCurve) DkgInitResult {
	return FfiConverterDkgInitResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_dkg_init(FfiConverterUint32INSTANCE.Lower(partyId), FfiConverterUint32INSTANCE.Lower(threshold), FfiConverterUint32INSTANCE.Lower(totalParties), FfiConverterEllipticCurveINSTANCE.Lower(curve), _uniffiStatus),
		}
	}))
}

func DkgInitWithSessionId(partyId uint32, threshold uint32, totalParties uint32, sessionId []uint8, curve EllipticCurve) DkgInitResult {
	return FfiConverterDkgInitResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_dkg_init_with_session_id(FfiConverterUint32INSTANCE.Lower(partyId), FfiConverterUint32INSTANCE.Lower(threshold), FfiConverterUint32INSTANCE.Lower(totalParties), FfiConverterSequenceUint8INSTANCE.Lower(sessionId), FfiConverterEllipticCurveINSTANCE.Lower(curve), _uniffiStatus),
		}
	}))
}

func DkgRound1(sessionState []uint8) DkgRoundResult {
	return FfiConverterDkgRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_dkg_round1(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), _uniffiStatus),
		}
	}))
}

func DkgRound2(sessionState []uint8, receivedMessages []PartyMessage) DkgRoundResult {
	return FfiConverterDkgRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_dkg_round2(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func DkgRound3(sessionState []uint8, receivedMessages []PartyMessage) DkgRoundResult {
	return FfiConverterDkgRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_dkg_round3(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func GetPublicKey(keyShare []uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_get_public_key(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), _uniffiStatus),
		}
	}))
}

func Init() {
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_dkls23_ffi_fn_func_init(_uniffiStatus)
		return false
	})
}

func RefreshFinalize(sessionState []uint8, receivedMessages []PartyMessage) RefreshFinalResult {
	return FfiConverterRefreshFinalResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_refresh_finalize(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func RefreshInit(keyShare []uint8, partyId uint32) RefreshInitResult {
	return FfiConverterRefreshInitResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_refresh_init(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), FfiConverterUint32INSTANCE.Lower(partyId), _uniffiStatus),
		}
	}))
}

func RefreshInitWithRefreshId(keyShare []uint8, partyId uint32, refreshId []uint8) RefreshInitResult {
	return FfiConverterRefreshInitResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_refresh_init_with_refresh_id(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), FfiConverterUint32INSTANCE.Lower(partyId), FfiConverterSequenceUint8INSTANCE.Lower(refreshId), _uniffiStatus),
		}
	}))
}

func RefreshRound1(sessionState []uint8) RefreshRoundResult {
	return FfiConverterRefreshRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_refresh_round1(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), _uniffiStatus),
		}
	}))
}

func RefreshRound2(sessionState []uint8, receivedMessages []PartyMessage) RefreshRoundResult {
	return FfiConverterRefreshRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_refresh_round2(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func RefreshRound3(sessionState []uint8, receivedMessages []PartyMessage) RefreshRoundResult {
	return FfiConverterRefreshRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_refresh_round3(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func RekeyFromSecret(secretKey []uint8, threshold uint32, totalParties uint32, curve EllipticCurve) RekeyResult {
	return FfiConverterRekeyResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_rekey_from_secret(FfiConverterSequenceUint8INSTANCE.Lower(secretKey), FfiConverterUint32INSTANCE.Lower(threshold), FfiConverterUint32INSTANCE.Lower(totalParties), FfiConverterEllipticCurveINSTANCE.Lower(curve), _uniffiStatus),
		}
	}))
}

func ResizeInit(keyShare []uint8, partyId uint32, newThreshold uint32, newTotalParties uint32, newPartyIds []uint32, curve EllipticCurve) ResizeInitResult {
	return FfiConverterResizeInitResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_resize_init(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), FfiConverterUint32INSTANCE.Lower(partyId), FfiConverterUint32INSTANCE.Lower(newThreshold), FfiConverterUint32INSTANCE.Lower(newTotalParties), FfiConverterSequenceUint32INSTANCE.Lower(newPartyIds), FfiConverterEllipticCurveINSTANCE.Lower(curve), _uniffiStatus),
		}
	}))
}

func ResizeRound1(sessionState []uint8) ResizeRoundResult {
	return FfiConverterResizeRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_resize_round1(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), _uniffiStatus),
		}
	}))
}

func ResizeRound2(sessionState []uint8, receivedMessages []PartyMessage) ResizeFinalResult {
	return FfiConverterResizeFinalResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_resize_round2(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func SignFinalize(sessionState []uint8, receivedMessages []PartyMessage) SignFinalResult {
	return FfiConverterSignFinalResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_sign_finalize(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func SignInit(keyShare []uint8, messageHash []uint8, signerPartyIds []uint32) SignInitResult {
	return FfiConverterSignInitResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_sign_init(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), FfiConverterSequenceUint8INSTANCE.Lower(messageHash), FfiConverterSequenceUint32INSTANCE.Lower(signerPartyIds), _uniffiStatus),
		}
	}))
}

func SignInitWithSignId(keyShare []uint8, messageHash []uint8, signerPartyIds []uint32, signId []uint8) SignInitResult {
	return FfiConverterSignInitResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_sign_init_with_sign_id(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), FfiConverterSequenceUint8INSTANCE.Lower(messageHash), FfiConverterSequenceUint32INSTANCE.Lower(signerPartyIds), FfiConverterSequenceUint8INSTANCE.Lower(signId), _uniffiStatus),
		}
	}))
}

func SignRound1(sessionState []uint8) SignRoundResult {
	return FfiConverterSignRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_sign_round1(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), _uniffiStatus),
		}
	}))
}

func SignRound2(sessionState []uint8, receivedMessages []PartyMessage) SignRoundResult {
	return FfiConverterSignRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_sign_round2(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func SignRound3(sessionState []uint8, receivedMessages []PartyMessage) SignRoundResult {
	return FfiConverterSignRoundResultINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_dkls23_ffi_fn_func_sign_round3(FfiConverterSequenceUint8INSTANCE.Lower(sessionState), FfiConverterSequencePartyMessageINSTANCE.Lower(receivedMessages), _uniffiStatus),
		}
	}))
}

func ValidateKeyShare(keyShare []uint8) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_dkls23_ffi_fn_func_validate_key_share(FfiConverterSequenceUint8INSTANCE.Lower(keyShare), _uniffiStatus)
	}))
}
