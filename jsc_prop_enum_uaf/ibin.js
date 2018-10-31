function Bin_Excpetion (message) {
	this.message = message;
	this.stack = (new Error()).stack;
};

Bin_Excpetion.prototype = Object.create(Error.prototype);
Bin_Excpetion.prototype.name = "BinHelper_Exception";

// f64 could be any value except NaN (0x7ff exponent and non zero mantissa)
// in which case it is always encoded as 0x7ff8000000000000.
// We will throw when attempting to encode NaN to a 64-bit value
var BinHelper = function() {
	this.buf = new ArrayBuffer(8);
	this.f64 = new Float64Array(this.buf);
	this.u32 = new Uint32Array(this.buf);
	this.u16 = new Uint16Array(this.buf);
	this.u8  = new Uint8Array(this.buf);
}

BinHelper.prototype.asciiToAddr = function (str) {

	for (var i=0; i<8; i++) {
		if (i < str.length)
			this.u8[i] = str.charCodeAt(i);
		else
			this.u8[i] = 0;
	}

	this.assertNaN();
	return this.f64[0];
}

BinHelper.prototype.uint8ArrToAddr = function (arr) {

	for (var i=0; i<8; i++) {
		if (i < arr.length) 
			this.u8[i] = arr[i];
		else
			this.u8[i] = 0;
	}

	this.assertNaN();
	return this.f64[0];
}

BinHelper.prototype.uint8ArrToU32 = function (arr) {

	for (var i=0; i<4; i++) {
		if (i < arr.length) 
			this.u8[i] = arr[i];
		else
			this.u8[i] = 0;
	}

	return this.u32[0];
}

BinHelper.prototype.assertNaN = function() {

	let hi = this.u32[1];
	let lo = this.u32[0];

	if ( ((hi & 0x7ff00000) == 0x7ff00000) && lo != 0 )
		throw new Bin_Excpetion("NaNs are not allowed");
}

BinHelper.prototype.toF64 = function (hi, lo) {

	this.u32[1] = hi;
	this.u32[0] = lo;

	this.assertNaN();
	return this.f64[0];
}

// for values greater then 0x0001000000000000
// we can place those into properties as JSValue,
// This method takes into account the adjustments made
// by jsc, so we get the actualy value we want as property
BinHelper.prototype.toF64JSValue = function (hi, lo) {

	if (hi < 0x10000) {
		throw new Bin_Excpetion("toF64JSValue failed hi < 0x10000");
	}

	this.u32[1] = hi - 0x10000;
	this.u32[0] = lo;

	this.assertNaN();
	return this.f64[0];
}

BinHelper.prototype.f64JSValue = function (ptr) {

	var hi = this.f64hi(ptr);
	var lo = this.f64lo(ptr);

	return this.toF64JSValue(hi, lo);
}

BinHelper.prototype.f64lo = function (f64) {
	this.f64[0] = f64;
	return this.u32[0];
}

BinHelper.prototype.f64hi = function (f64) {
	this.f64[0] = f64;
	return this.u32[1];
}

BinHelper.prototype.f64ToStr = function (f64) {

	this.f64[0] = f64;
	this.assertNaN();

	var prefix = '';
	let i = 24;

	if (this.u32[0] <= 0xfffffff)
		prefix += '0';

	while ((this.u32[0] >> i) == 0) {
		i -= 4;
		prefix += '0';
		if (i == 0)
			break;
	}

	return this.u32[1].toString(0x10) + prefix + this.u32[0].toString(0x10);
}

BinHelper.prototype.u16StrToUint8Array = function (str) {

	var bytes = new Uint8Array(str.length*2);

	for (var i=0; i<str.length; i++) {
		var code = str.charCodeAt(i);
		bytes[i*2] = code & 0xff;
		bytes[i*2 + 1] = code >> 8;
	}

	return bytes;
}

BinHelper.prototype.asciiToUint8Array = function (str) {

	var bytes = new Uint8Array(str.length);

	for (var i=0; i<str.length; i++) {
		var code = str.charCodeAt(i);
		bytes[i] = code & 0xff;
	}

	return bytes;
}


BinHelper.prototype.uint8ArrayToStr = function (uint8Array) {
	var arr = Array.from(uint8Array)
		return String.fromCharCode(...arr);
}

BinHelper.prototype.f64ToUint8Array = function (f64) {
	this.f64[0] = f64;
	return new Uint8Array(this.buf);
}

BinHelper.prototype.f64AddU32 = function(f64, offset) {

	let addend = Math.sign(offset)*this.toF64(0, Math.abs(offset));
	return f64 + addend;
}

BinHelper.prototype.f64AndLo = function(f64, mask) {

	this.f64[0] = f64;
	this.u32[0] &= mask;
	return this.f64[0];
}

BinHelper.prototype.uint8Find = function(arr, niddle, offset=0) {

	if (niddle.byteLength > arr.byteLength)
		return -1;

	function atPos(pos) {
		for (let j=0; j<niddle.byteLength; j++) {
			if (arr[pos+j] != niddle[j]) {
				return false;
			}
		}

		return true;
	}

	for (let i=offset; i < (arr.byteLength - niddle.byteLength); i++) {
		if (atPos(i))
			return i;
	}

	return -1;
}

BinHelper.prototype.uint8FindReverse = function(arr, niddle) {

	if (niddle.byteLength > arr.byteLength)
		return -1;

	function atPos(pos) {
		for (let j=0; j<niddle.byteLength; j++) {
			if (arr[pos+j] != niddle[j]) {
				return false;
			}
		}

		return true;
	}

	for (let i=(arr.byteLength - niddle.byteLength); i>0; i--) {
		if (atPos(i))
			return i;
	}

	return -1;
}

BinHelper.prototype.__lshiftF64 = function (shift) {

	this.u16[3] = this.u16[3] << shift;

	let extra = this.u16[2] & (0xffff << (16-shift));
	extra = extra >> (16 - shift);
	this.u16[3] = this.u16[3] | extra; 
	this.u16[2] = this.u16[2] << shift;

	extra = this.u16[1] & (0xffff << (16-shift));
	extra = extra >> (16 - shift);
	this.u16[2] = this.u16[2] | extra; 
	this.u16[1] = this.u16[1] << shift;

	extra = this.u16[0] & (0xffff << (16-shift));
	extra = extra >> (16 - shift);
	this.u16[1] = this.u16[1] | extra; 
	this.u16[0] = this.u16[0] << shift;
}

BinHelper.prototype.lshiftF64 = function (f64, shift) {

	this.f64[0] = f64;

	if (shift <= 16) {
		this.__lshiftF64(shift);
		return this.f64[0];
	}

	while (shift > 16) {
		this.__lshiftF64(16);
		shift -= 16;
	}

	this.__lshiftF64(shift);

	return this.f64[0];
}


BinHelper.prototype.f64OrLo = function(f64, mask) {
	this.f64[0] = f64;
	this.u32[0] |= mask;
	return this.f64[0];
}

BinHelper.prototype.f64Xor = function (f1, f2) {

	var hi1 = this.f64hi(f1);
	var lo1 = this.f64lo(f1);

	var hi2 = this.f64hi(f2);
	var lo2 = this.f64lo(f2);

	return this.toF64(hi1 ^ hi2, lo1 ^ lo2);
}

let bh = new BinHelper();

// vim: tabstop=4:noexpandtab:shiftwidth=4
