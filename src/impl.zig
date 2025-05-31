const cs = @import("capstone-c");

pub const err = @import("error.zig");
pub const insn = @import("insn.zig");
pub const setup = @import("setup.zig");
pub const enums = @import("enums.zig");
const iter = @import("iter.zig");

pub const Iter = iter.Iter;
pub const IterManaged = iter.IterManaged;
pub const Handle = cs.csh;

const SemanticVersion = @import("std").SemanticVersion;
pub fn version() SemanticVersion {
    var major: c_uint = 0;
    var minor: c_uint = 0;

    _ = cs.cs_version(@ptrCast(&major), @ptrCast(&minor));
    return SemanticVersion{
        .major = @intCast(major),
        .minor = @intCast(minor),
        .patch = 0, // Capstone does not provide patch version
    };
}

pub fn support(query: c_int) bool {
    return cs.cs_support(query);
}

/// Please close the handle after usage by using: `close`
pub fn open(arch: enums.Arch, mode: enums.Mode) err.CapstoneError!Handle {
    var handle: Handle = 0;

    return err.toError(cs.cs_open(@intFromEnum(arch), @intFromEnum(mode), &handle)) orelse handle;
}

/// Closes a handle
pub fn close(handle: *Handle) err.CapstoneError!void {
    return err.toError(cs.cs_close(@ptrCast(handle))) orelse return;
}

pub fn option(handle: ?Handle, @"type": enums.Type, value: usize) err.CapstoneError!void {
    return err.toError(cs.cs_option(handle orelse 0, @intFromEnum(@"type"), value)) orelse return;
}

pub fn errno(handle: Handle) err.CapstoneError!void {
    return err.toError(cs.cs_errno(handle)) orelse return;
}

pub fn strerror(code: ?err.CapstoneError) ?[*:0]const u8 {
    if (code) |e| {
        const err_as_int = err.fromError(e);
        return @ptrCast(cs.cs_strerror(err_as_int));
    }

    return null;
}

/// The owner takes responsibility of the pointer.
/// Please free with `free`
pub fn disasm(handle: Handle, code: []const u8, address: usize, count: usize) err.CapstoneError![]insn.Insn {
    var ins: [*]insn.Insn = undefined;

    const res_count = cs.cs_disasm(handle, code.ptr, code.len, address, count, @ptrCast(&ins));

    errno(handle) catch |n| return n;

    return ins[0..res_count];
}

/// Equivilent to cs_free
/// Only accepts `[]insn.Insn` or `*insn.Insn` types.
pub fn free(ins: anytype) void {
    const type_info = @typeInfo(@TypeOf(ins));

    if (type_info == .pointer) {
        const pointer_type = type_info.pointer;
        if (pointer_type.child != insn.Insn and pointer_type.size != .one) {
            @compileError("`ins` type doesn't match `[]insn.Insn` or `*insn.Insn`");
        }
        cs.cs_free(@ptrCast(ins), 1);
    } else if (type_info == .array) {
        const array_type = type_info.array;
        if (array_type.child != insn.Insn) {
            @compileError("`ins` type doesn't match `[]insn.Insn` or `*insn.Insn`");
        }
        cs.cs_free(@ptrCast(ins.ptr), ins.len);
    } else {
        @compileError("`ins` type doesn't match `[]insn.Insn` or `*insn.Insn`");
    }
}

/// Equivilent to cs_malloc
pub fn malloc(handle: Handle) !*insn.Insn {
    const ins: ?*insn.Insn = @ptrCast(cs.cs_malloc(handle));
    return if (ins) |i| return i else return error.OutOfMemory;
}

/// Same as the normal Variant, but does the allocation for you.
pub fn disasmIterManaged(handle: Handle, code: []const u8, address: u64) !IterManaged {
    return IterManaged.init(handle, code, address);
}

/// Return an Iter object
/// Does not yet consume any element.
pub fn disasmIter(handle: Handle, code: []const u8, address: u64, ins: *insn.Insn) Iter {
    return Iter{
        .handle = handle,
        .code = code,
        .original_code = code,
        .original_address = address,
        .address = address,
        .insn = ins,
    };
}

pub fn regName(handle: Handle, reg_id: c_uint) [*:0]const u8 {
    return cs.cs_reg_name(handle, reg_id);
}

pub fn insnName(handle: Handle, insn_id: c_uint) [*:0]const u8 {
    return cs.cs_insn_name(handle, insn_id);
}

pub fn groupName(handle: Handle, group_id: c_uint) [*:0]const u8 {
    return cs.cs_group_name(handle, group_id);
}

pub fn insnGroup(handle: Handle, ins: *const insn.Insn, group_id: c_uint) bool {
    return cs.cs_insn_group(handle, @ptrCast(ins), group_id);
}

pub fn regRead(handle: Handle, ins: *const insn.Insn, reg_id: c_uint) bool {
    return cs.cs_reg_read(handle, @ptrCast(ins), reg_id);
}

pub fn regWrite(handle: Handle, ins: *const insn.Insn, reg_id: c_uint) bool {
    return cs.cs_reg_write(handle, @ptrCast(ins), reg_id);
}

pub fn opCount(handle: Handle, ins: *const insn.Insn, op_type: c_uint) c_int {
    return cs.cs_op_count(handle, @ptrCast(ins), op_type);
}

pub fn opIndex(handle: Handle, ins: *const insn.Insn, op_type: c_uint, position: c_uint) c_int {
    return cs.cs_op_index(handle, @ptrCast(ins), op_type, position);
}

pub const Regs = [64]u16;
pub fn regsAccess(
    handle: Handle,
    ins: *const insn.Insn,
    regs_read: *Regs,
    regs_read_count: *u8,
    regs_write: *Regs,
    regs_write_count: *u8,
) err.CapstoneError!void {
    return err.toError(cs.cs_regs_access(
        handle,
        @ptrCast(ins),
        @ptrCast(regs_read[0..].ptr),
        @ptrCast(regs_read_count),
        @ptrCast(regs_write[0..].ptr),
        @ptrCast(regs_write_count),
    )) orelse return;
}

test {
    @import("std").testing.refAllDecls(@This());
    @import("std").testing.refAllDecls(@import("error.zig"));
    @import("std").testing.refAllDecls(@import("insn.zig"));
    @import("std").testing.refAllDecls(@import("setup.zig"));
}

test "malloc and free" {
    var handle = try open(.X86, .@"16");
    defer close(&handle) catch {};
    const ins = try malloc(handle);
    defer free(ins);

    const disass = try disasm(handle, "\x75\x14", 0x1000, 0);
    defer free(disass);
    try @import("std").testing.expectEqual(1, disass.len);
}
