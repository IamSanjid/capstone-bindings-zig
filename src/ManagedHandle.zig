const builtin = @import("builtin");
const std = @import("std");

const cs = @import("capstone-c");

const err = @import("error.zig");
const insn = @import("insn.zig");
const enums = @import("enums.zig");
const impl = @import("impl.zig");

const iter = @import("iter.zig");

const Allocator = std.mem.Allocator;

// To avoid heap allocations...
const tmp_storage = if (builtin.single_threaded)
    struct {
        var detail: insn.Detail = std.mem.zeroes(insn.Detail);
        var ins: insn.Insn = std.mem.zeroes(insn.Insn);
        fn getIns() *insn.Insn {
            ins.detail = &detail;
            return &ins;
        }
    }
else
    struct {
        threadlocal var detail: insn.Detail = std.mem.zeroes(insn.Detail);
        threadlocal var ins: insn.Insn = std.mem.zeroes(insn.Insn);
        fn getIns() *insn.Insn {
            ins.detail = &detail;
            return &ins;
        }
    };

const Self = @This();

pub const Options = struct {
    /// Assembly output syntax
    syntax: enums.Syntax = .DEFAULT,
    /// Break down instruction structure into details
    detail: bool = false,
    /// Skip data when disassembling. Then engine is in SKIPDATA mode.
    skipdata: bool = false,
    /// Setup user-defined function for SKIPDATA option
    /// The pointers must be valid till the handle is closed.
    skipdata_setup: ?SkipDataOption = null,
    /// Customize instruction mnemonic
    /// Must be valid till the handle is closed if set.
    mnemonic: []const MnemonicOption = &.{},
    /// print immediate operands in unsigned form
    unsigned: bool = false,
    /// ARM, prints branch immediates without offset.
    no_branch_offset: bool = false,

    // cs_opt_mnem
    pub const MnemonicOption = extern struct {
        id: c_uint,
        mnemonic: [*:0]const u8,
    };
    // cs_skipdata
    pub const SkipDataOption = extern struct {
        mnemonic: [*:0]const u8,
        callback: ?*const fn ([*c]const u8, usize, usize, ?*anyopaque) callconv(.c) usize,
        user_data: ?*anyopaque = null,
    };
};

native: impl.Handle,
detail_on: bool,

pub fn init(arch: enums.Arch, mode: cs.cs_mode, options: Options) !Self {
    const handle = try impl.open(arch, mode);

    if (options.syntax != .DEFAULT) {
        try impl.option(handle, .SYNTAX, @intFromEnum(options.syntax));
    }

    if (options.detail) {
        try impl.option(handle, .DETAIL, cs.CS_OPT_ON);
    }

    if (options.skipdata) {
        try impl.option(handle, .SKIPDATA, cs.CS_OPT_ON);
    }

    if (options.skipdata_setup) |setup| {
        // cs_option copies the values.
        try impl.option(handle, .SKIPDATA_SETUP, @intFromPtr(&setup));
    }

    if (options.unsigned) {
        try impl.option(handle, .UNSIGNED, cs.CS_OPT_ON);
    }

    if (options.no_branch_offset) {
        try impl.option(handle, .NO_BRANCH_OFFSET, cs.CS_OPT_ON);
    }

    if (options.mnemonic.len > 0) {
        try impl.option(handle, .MNEMONIC, @intFromPtr(options.mnemonic.ptr));
    }

    return Self{ .native = handle, .detail_on = options.detail };
}

/// Allocates using the cs_malloc function or the user defined one which is set through cs_option/setup.initCapstone(Manually).
/// Should be freed using cs_free, capstone provided free function or the user defined one if set through option.
pub fn disasm(self: Self, code: []const u8, address: usize, count: usize) err.CapstoneError![]insn.Insn {
    return impl.disasm(self.native, code, address, count);
}

/// Copies using zig user-land allocator and frees the cs_malloc'd memory.
pub fn disasmAlloc(self: Self, allocator: std.mem.Allocator, code: []const u8, address: usize, count: usize) ![]insn.Insn {
    const disass = try impl.disasm(self.native, code, address, count);
    defer impl.free(disass);
    return allocator.dupe(insn.Insn, disass);
}

/// Uses global/threadlocal storage to avoid heap allocations for the single Insn struct.
pub fn disasmIter(self: Self, code: []const u8, address: u64) iter.IterUnmanaged {
    return impl.disasmIter(self.native, code, address, tmp_storage.getIns());
}

/// Same as `impl.createInsn` but has more context.
pub fn createInsn(self: Self, allocator: Allocator) !*insn.Insn {
    return impl.createInsn(allocator, self.detail_on);
}

/// Creates a duplicate of the provided Insn object using the provided allocator.
/// The owner takes responsibility of the pointer.
/// Must be destroyed with `destroyInsn`.
pub fn dupeInsn(self: Self, allocator: Allocator, ins: *const insn.Insn) !*insn.Insn {
    var new_ins = try self.createInsn(allocator);
    const new_detail = new_ins.detail;
    new_ins.* = ins.*;

    if (self.detail_on and ins.detail == null) {
        std.io.getStdErr().writer().print("Cannot duplicate `ins`, doesn't have detail.\n", .{}) catch {};
        return error.NotEnoughFields;
    }

    if (new_detail != null) {
        new_detail.?.* = ins.detail.?.*;
    }
    new_ins.detail = new_detail;

    return new_ins;
}

/// Same as impl.destroyInsn.
pub fn destroyInsn(_: Self, allocator: Allocator, ins: *insn.Insn) void {
    impl.destroyInsn(allocator, ins);
}

pub fn deinit(self: *Self) void {
    impl.close(&self.native) catch |e| {
        std.io.getStdErr().writer().print("Failed to close handle: {any}\n", .{impl.strerror(e)}) catch {};
    };
}

test "with options" {
    const code = "\x75\x14";

    var handle = try init(.X86, @intFromEnum(enums.Mode.@"64"), .{
        .syntax = .INTEL,
        .detail = true,
        .mnemonic = &.{.{ .id = cs.X86_INS_JNE, .mnemonic = "jnz" }},
    });
    defer handle.deinit();

    const disass = try handle.disasm(code, 0x1000, 0);
    defer impl.free(disass);

    try std.testing.expectEqual(1, disass.len);
    try std.testing.expect(disass[0].detail != null);
    try std.testing.expectEqualStrings("jnz", disass[0].mnemonic[0..3]);
}

test "disasm iter" {
    const code = "\x75\x14";

    var handle = try init(.X86, @intFromEnum(enums.Mode.@"64"), .{
        .syntax = .INTEL,
        .detail = true,
        .mnemonic = &.{.{ .id = cs.X86_INS_JNE, .mnemonic = "jnz" }},
    });
    defer handle.deinit();

    var dis_iter = handle.disasmIter(code, 0x1000);
    const ins = dis_iter.next().?;

    try std.testing.expect(ins.detail != null);
    try std.testing.expectEqualStrings("jnz", ins.mnemonic[0..3]);
}

test "create, dupe and destroy Insn" {
    const testing = @import("std").testing;
    const allocator = testing.allocator;

    var handle = try init(.X86, @intFromEnum(enums.Mode.@"64"), .{
        .syntax = .INTEL,
        .detail = true,
    });
    defer handle.deinit();

    const ins = try handle.createInsn(allocator);
    defer handle.destroyInsn(allocator, ins);

    ins.id = 0x1234;
    ins.address = 0x1000;
    ins.size = 2;
    ins.detail.?.groups_count = 2;

    const duped_ins = try handle.dupeInsn(allocator, ins);
    defer handle.destroyInsn(allocator, duped_ins);

    try testing.expectEqual(ins.id, duped_ins.id);
    try testing.expectEqual(ins.address, duped_ins.address);
    try testing.expectEqual(ins.size, duped_ins.size);
    try testing.expectEqual(ins.detail.?.groups_count, duped_ins.detail.?.groups_count);
    try testing.expect(ins.detail != duped_ins.detail);
}
