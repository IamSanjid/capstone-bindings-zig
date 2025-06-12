# capstone-bindings-zig

## Introduction
Capstone natively works with Zig because of `translate-c`, but i always find it more pleasent to use
Zig's features whenever i write anything, so i decided to create those bindings.

## Example
Simple example, i believe i snatched it from some of the tests in capstone itself.

## Remarks
> [!WARNING]
> The bindings should fully work, however they are not battle-tested yet.
> If you encounter any Issues / Bugs / API Concerns, please open an Issue.

## Future plans
The API is probably not 100% as i want it yet, so changes are to be expected, and that's where especially you,
the user comes into play. If you have ideas on how to improve the API design, don't shy away from creating an
issue.

## Example
```zig
const std = @import("std");
const cs = @import("capstone-z");

const CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\xea\xbe\xad\xde\xff\x25\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff";

pub fn main() !void {
    var handle = try cs.ManagedHandle.init(cs.Arch.X86, @intFromEnum(cs.Mode.@"64"), .{
        .syntax = .INTEL,
        .detail = true,
        .mnemonic = &.{.{ .id = cs.c.X86_INS_JMP, .mnemonic = "our_jmp" }},
    });
    defer handle.deinit();

    var iter = handle.disasmIter(CODE, 0x1000);
    var index: usize = 0;
    while (iter.next()) |insn| : (index += 1) {
        std.debug.print("{d}: 0x{x}\t{s}\t{s}\n", .{ index, insn.address, insn.mnemonic, insn.op_str });
    }
}
```

that gives the following output:
```
0: 0x1000       push    rbp
1: 0x1001       mov     rax, qword ptr [rip + 0x13b8]
2: 0x1008       our_jmp 0xffffffffdeadcef7
3: 0x100d       our_jmp qword ptr [rip + 0x123]
4: 0x1013       call    0xffffffffdeadcef7
5: 0x1018       je      0x1019
```

## License
I am not an expert on licenses, but from my understanding bindings can have a different license.
So if you're using it in your project, make sure to actually verify that it is compatible with the
actual [capstone license](https://github.com/capstone-engine/capstone#License).
