package rpm

// #include <rpm.h>
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
		C.ffi_rpm_rustbuffer_free(cb, status)
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
		return C.ffi_rpm_rustbuffer_from_bytes(foreign, status)
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
		return C.ffi_rpm_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("rpm: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rpm_checksum_func_wrapped_rpm_combine_shares_and_mask(uniffiStatus)
		})
		if checksum != 14550 {
			// If this happens try cleaning and rebuilding your project
			panic("rpm: uniffi_rpm_checksum_func_wrapped_rpm_combine_shares_and_mask: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rpm_checksum_func_wrapped_rpm_finalize(uniffiStatus)
		})
		if checksum != 59972 {
			// If this happens try cleaning and rebuilding your project
			panic("rpm: uniffi_rpm_checksum_func_wrapped_rpm_finalize: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rpm_checksum_func_wrapped_rpm_generate_initial_shares(uniffiStatus)
		})
		if checksum != 49132 {
			// If this happens try cleaning and rebuilding your project
			panic("rpm: uniffi_rpm_checksum_func_wrapped_rpm_generate_initial_shares: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rpm_checksum_func_wrapped_rpm_permute(uniffiStatus)
		})
		if checksum != 21224 {
			// If this happens try cleaning and rebuilding your project
			panic("rpm: uniffi_rpm_checksum_func_wrapped_rpm_permute: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rpm_checksum_func_wrapped_rpm_sketch_propose(uniffiStatus)
		})
		if checksum != 29586 {
			// If this happens try cleaning and rebuilding your project
			panic("rpm: uniffi_rpm_checksum_func_wrapped_rpm_sketch_propose: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rpm_checksum_func_wrapped_rpm_sketch_verify(uniffiStatus)
		})
		if checksum != 1146 {
			// If this happens try cleaning and rebuilding your project
			panic("rpm: uniffi_rpm_checksum_func_wrapped_rpm_sketch_verify: UniFFI API checksum mismatch")
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

type WrappedCombinedSharesAndMask struct {
	Ms   [][][][][]uint8
	Rs   [][][]uint8
	Mrms [][][][][]uint8
}

func (r *WrappedCombinedSharesAndMask) Destroy() {
	FfiDestroyerSequenceSequenceSequenceSequenceSequenceUint8{}.Destroy(r.Ms)
	FfiDestroyerSequenceSequenceSequenceUint8{}.Destroy(r.Rs)
	FfiDestroyerSequenceSequenceSequenceSequenceSequenceUint8{}.Destroy(r.Mrms)
}

type FfiConverterTypeWrappedCombinedSharesAndMask struct{}

var FfiConverterTypeWrappedCombinedSharesAndMaskINSTANCE = FfiConverterTypeWrappedCombinedSharesAndMask{}

func (c FfiConverterTypeWrappedCombinedSharesAndMask) Lift(rb RustBufferI) WrappedCombinedSharesAndMask {
	return LiftFromRustBuffer[WrappedCombinedSharesAndMask](c, rb)
}

func (c FfiConverterTypeWrappedCombinedSharesAndMask) Read(reader io.Reader) WrappedCombinedSharesAndMask {
	return WrappedCombinedSharesAndMask{
		FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedCombinedSharesAndMask) Lower(value WrappedCombinedSharesAndMask) RustBuffer {
	return LowerIntoRustBuffer[WrappedCombinedSharesAndMask](c, value)
}

func (c FfiConverterTypeWrappedCombinedSharesAndMask) Write(writer io.Writer, value WrappedCombinedSharesAndMask) {
	FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Write(writer, value.Ms)
	FfiConverterSequenceSequenceSequenceUint8INSTANCE.Write(writer, value.Rs)
	FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Write(writer, value.Mrms)
}

type FfiDestroyerTypeWrappedCombinedSharesAndMask struct{}

func (_ FfiDestroyerTypeWrappedCombinedSharesAndMask) Destroy(value WrappedCombinedSharesAndMask) {
	value.Destroy()
}

type WrappedInitialShares struct {
	Ms [][][][][][]uint8
	Rs [][][][]uint8
}

func (r *WrappedInitialShares) Destroy() {
	FfiDestroyerSequenceSequenceSequenceSequenceSequenceSequenceUint8{}.Destroy(r.Ms)
	FfiDestroyerSequenceSequenceSequenceSequenceUint8{}.Destroy(r.Rs)
}

type FfiConverterTypeWrappedInitialShares struct{}

var FfiConverterTypeWrappedInitialSharesINSTANCE = FfiConverterTypeWrappedInitialShares{}

func (c FfiConverterTypeWrappedInitialShares) Lift(rb RustBufferI) WrappedInitialShares {
	return LiftFromRustBuffer[WrappedInitialShares](c, rb)
}

func (c FfiConverterTypeWrappedInitialShares) Read(reader io.Reader) WrappedInitialShares {
	return WrappedInitialShares{
		FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedInitialShares) Lower(value WrappedInitialShares) RustBuffer {
	return LowerIntoRustBuffer[WrappedInitialShares](c, value)
}

func (c FfiConverterTypeWrappedInitialShares) Write(writer io.Writer, value WrappedInitialShares) {
	FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Write(writer, value.Ms)
	FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE.Write(writer, value.Rs)
}

type FfiDestroyerTypeWrappedInitialShares struct{}

func (_ FfiDestroyerTypeWrappedInitialShares) Destroy(value WrappedInitialShares) {
	value.Destroy()
}

type WrappedSketchProposal struct {
	Mp [][][][]uint8
	Rp [][]uint8
}

func (r *WrappedSketchProposal) Destroy() {
	FfiDestroyerSequenceSequenceSequenceSequenceUint8{}.Destroy(r.Mp)
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.Rp)
}

type FfiConverterTypeWrappedSketchProposal struct{}

var FfiConverterTypeWrappedSketchProposalINSTANCE = FfiConverterTypeWrappedSketchProposal{}

func (c FfiConverterTypeWrappedSketchProposal) Lift(rb RustBufferI) WrappedSketchProposal {
	return LiftFromRustBuffer[WrappedSketchProposal](c, rb)
}

func (c FfiConverterTypeWrappedSketchProposal) Read(reader io.Reader) WrappedSketchProposal {
	return WrappedSketchProposal{
		FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedSketchProposal) Lower(value WrappedSketchProposal) RustBuffer {
	return LowerIntoRustBuffer[WrappedSketchProposal](c, value)
}

func (c FfiConverterTypeWrappedSketchProposal) Write(writer io.Writer, value WrappedSketchProposal) {
	FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE.Write(writer, value.Mp)
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.Rp)
}

type FfiDestroyerTypeWrappedSketchProposal struct{}

func (_ FfiDestroyerTypeWrappedSketchProposal) Destroy(value WrappedSketchProposal) {
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

type FfiConverterSequenceSequenceSequenceUint8 struct{}

var FfiConverterSequenceSequenceSequenceUint8INSTANCE = FfiConverterSequenceSequenceSequenceUint8{}

func (c FfiConverterSequenceSequenceSequenceUint8) Lift(rb RustBufferI) [][][]uint8 {
	return LiftFromRustBuffer[[][][]uint8](c, rb)
}

func (c FfiConverterSequenceSequenceSequenceUint8) Read(reader io.Reader) [][][]uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([][][]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterSequenceSequenceUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceSequenceSequenceUint8) Lower(value [][][]uint8) RustBuffer {
	return LowerIntoRustBuffer[[][][]uint8](c, value)
}

func (c FfiConverterSequenceSequenceSequenceUint8) Write(writer io.Writer, value [][][]uint8) {
	if len(value) > math.MaxInt32 {
		panic("[][][]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceSequenceSequenceUint8 struct{}

func (FfiDestroyerSequenceSequenceSequenceUint8) Destroy(sequence [][][]uint8) {
	for _, value := range sequence {
		FfiDestroyerSequenceSequenceUint8{}.Destroy(value)
	}
}

type FfiConverterSequenceSequenceSequenceSequenceUint8 struct{}

var FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE = FfiConverterSequenceSequenceSequenceSequenceUint8{}

func (c FfiConverterSequenceSequenceSequenceSequenceUint8) Lift(rb RustBufferI) [][][][]uint8 {
	return LiftFromRustBuffer[[][][][]uint8](c, rb)
}

func (c FfiConverterSequenceSequenceSequenceSequenceUint8) Read(reader io.Reader) [][][][]uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([][][][]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterSequenceSequenceSequenceUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceSequenceSequenceSequenceUint8) Lower(value [][][][]uint8) RustBuffer {
	return LowerIntoRustBuffer[[][][][]uint8](c, value)
}

func (c FfiConverterSequenceSequenceSequenceSequenceUint8) Write(writer io.Writer, value [][][][]uint8) {
	if len(value) > math.MaxInt32 {
		panic("[][][][]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterSequenceSequenceSequenceUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceSequenceSequenceSequenceUint8 struct{}

func (FfiDestroyerSequenceSequenceSequenceSequenceUint8) Destroy(sequence [][][][]uint8) {
	for _, value := range sequence {
		FfiDestroyerSequenceSequenceSequenceUint8{}.Destroy(value)
	}
}

type FfiConverterSequenceSequenceSequenceSequenceSequenceUint8 struct{}

var FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE = FfiConverterSequenceSequenceSequenceSequenceSequenceUint8{}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceUint8) Lift(rb RustBufferI) [][][][][]uint8 {
	return LiftFromRustBuffer[[][][][][]uint8](c, rb)
}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceUint8) Read(reader io.Reader) [][][][][]uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([][][][][]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceUint8) Lower(value [][][][][]uint8) RustBuffer {
	return LowerIntoRustBuffer[[][][][][]uint8](c, value)
}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceUint8) Write(writer io.Writer, value [][][][][]uint8) {
	if len(value) > math.MaxInt32 {
		panic("[][][][][]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceSequenceSequenceSequenceSequenceUint8 struct{}

func (FfiDestroyerSequenceSequenceSequenceSequenceSequenceUint8) Destroy(sequence [][][][][]uint8) {
	for _, value := range sequence {
		FfiDestroyerSequenceSequenceSequenceSequenceUint8{}.Destroy(value)
	}
}

type FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8 struct{}

var FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8INSTANCE = FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8{}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8) Lift(rb RustBufferI) [][][][][][]uint8 {
	return LiftFromRustBuffer[[][][][][][]uint8](c, rb)
}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8) Read(reader io.Reader) [][][][][][]uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([][][][][][]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8) Lower(value [][][][][][]uint8) RustBuffer {
	return LowerIntoRustBuffer[[][][][][][]uint8](c, value)
}

func (c FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8) Write(writer io.Writer, value [][][][][][]uint8) {
	if len(value) > math.MaxInt32 {
		panic("[][][][][][]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceSequenceSequenceSequenceSequenceSequenceUint8 struct{}

func (FfiDestroyerSequenceSequenceSequenceSequenceSequenceSequenceUint8) Destroy(sequence [][][][][][]uint8) {
	for _, value := range sequence {
		FfiDestroyerSequenceSequenceSequenceSequenceSequenceUint8{}.Destroy(value)
	}
}

func WrappedRpmCombineSharesAndMask(ms [][][][][][]uint8, rs [][][][]uint8, size uint64, depth uint64, dealers uint64) WrappedCombinedSharesAndMask {
	return FfiConverterTypeWrappedCombinedSharesAndMaskINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_rpm_fn_func_wrapped_rpm_combine_shares_and_mask(FfiConverterSequenceSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Lower(ms), FfiConverterSequenceSequenceSequenceSequenceUint8INSTANCE.Lower(rs), FfiConverterUint64INSTANCE.Lower(size), FfiConverterUint64INSTANCE.Lower(depth), FfiConverterUint64INSTANCE.Lower(dealers), _uniffiStatus)
	}))
}

func WrappedRpmFinalize(input [][][]uint8, parties []uint64) [][]uint8 {
	return FfiConverterSequenceSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_rpm_fn_func_wrapped_rpm_finalize(FfiConverterSequenceSequenceSequenceUint8INSTANCE.Lower(input), FfiConverterSequenceUint64INSTANCE.Lower(parties), _uniffiStatus)
	}))
}

func WrappedRpmGenerateInitialShares(size uint64, depth uint64, dealers uint64, players uint64) WrappedInitialShares {
	return FfiConverterTypeWrappedInitialSharesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_rpm_fn_func_wrapped_rpm_generate_initial_shares(FfiConverterUint64INSTANCE.Lower(size), FfiConverterUint64INSTANCE.Lower(depth), FfiConverterUint64INSTANCE.Lower(dealers), FfiConverterUint64INSTANCE.Lower(players), _uniffiStatus)
	}))
}

func WrappedRpmPermute(maskedInputShares [][][]uint8, mb [][][][][]uint8, rb [][][]uint8, mrmb [][][][][]uint8, depthIndex uint64, parties []uint64) [][][]uint8 {
	return FfiConverterSequenceSequenceSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_rpm_fn_func_wrapped_rpm_permute(FfiConverterSequenceSequenceSequenceUint8INSTANCE.Lower(maskedInputShares), FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Lower(mb), FfiConverterSequenceSequenceSequenceUint8INSTANCE.Lower(rb), FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Lower(mrmb), FfiConverterUint64INSTANCE.Lower(depthIndex), FfiConverterSequenceUint64INSTANCE.Lower(parties), _uniffiStatus)
	}))
}

func WrappedRpmSketchPropose(m [][][][][]uint8, r [][][]uint8) WrappedSketchProposal {
	return FfiConverterTypeWrappedSketchProposalINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_rpm_fn_func_wrapped_rpm_sketch_propose(FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Lower(m), FfiConverterSequenceSequenceSequenceUint8INSTANCE.Lower(r), _uniffiStatus)
	}))
}

func WrappedRpmSketchVerify(mcs [][][][][]uint8, rcs [][][]uint8, dealers uint64) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rpm_fn_func_wrapped_rpm_sketch_verify(FfiConverterSequenceSequenceSequenceSequenceSequenceUint8INSTANCE.Lower(mcs), FfiConverterSequenceSequenceSequenceUint8INSTANCE.Lower(rcs), FfiConverterUint64INSTANCE.Lower(dealers), _uniffiStatus)
	}))
}
