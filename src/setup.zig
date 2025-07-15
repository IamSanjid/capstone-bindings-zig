const builtin = @import("builtin");
const std = @import("std");

const insn = @import("insn.zig");
const err = @import("error.zig");

const cs = @import("capstone-c");

// TODO: Use std.builtin.VaList later for windows x86_64, it's disabled currently in the zig's builtin since 0.14.1
const VaList = if (builtin.os.tag == .windows and builtin.cpu.arch == .x86_64)
    cs.__builtin_va_list
else
    std.builtin.VaList;

pub const MallocFunction = ?*const fn (usize) callconv(.c) ?*anyopaque;
pub const CallocFunction = ?*const fn (usize, usize) callconv(.c) ?*anyopaque;
pub const ReallocFunction = ?*const fn (?*anyopaque, usize) callconv(.c) ?*anyopaque;
pub const FreeFunction = ?*const fn (?*anyopaque) callconv(.c) void;
pub const VsnprintfFunction = ?*const fn ([*]u8, usize, [*]const u8, [*]VaList) callconv(.c) c_int;

var ALLOCATOR: ?std.mem.Allocator = null;

const PtrLen = usize;
const PtrAddress = usize;
const AllocationTable = std.AutoArrayHashMapUnmanaged(PtrAddress, PtrLen);
var ALLOCATION_TABLE: AllocationTable = .{};

fn malloc(size: usize) callconv(.c) ?*anyopaque {
    if (ALLOCATOR) |alloc| {
        const allocated = if (builtin.zig_version.major == 0 and builtin.zig_version.minor == 14)
            alloc.alignedAlloc(u8, 16, size) catch return null
        else
            alloc.alignedAlloc(u8, .@"16", size) catch return null;
        ALLOCATION_TABLE.put(alloc, @intFromPtr(allocated.ptr), allocated.len) catch @panic("OOM");
        return @ptrCast(allocated.ptr);
    } else {
        @panic("Call `initCapstone` first");
    }
}

fn calloc(size: usize, elements: usize) callconv(.c) ?*anyopaque {
    if (ALLOCATOR) |alloc| {
        const allocated = alloc.alloc(u8, elements * size) catch return null;
        ALLOCATION_TABLE.put(alloc, @intFromPtr(allocated.ptr), allocated.len) catch @panic("OOM");
        for (allocated) |*element| {
            element.* = '\x00';
        }
        return @ptrCast(allocated.ptr);
    } else {
        @panic("Call `initCapstone` first");
    }
}

fn realloc(ptr: ?*anyopaque, new_size: usize) callconv(.c) ?*anyopaque {
    if (ptr) |p| {
        if (ALLOCATOR) |alloc| {
            const prior = ALLOCATION_TABLE.fetchSwapRemove(@intFromPtr(p)) orelse @panic("Realloc called without element in list");
            const actual: [*]u8 = @ptrFromInt(prior.key);
            const as_fat_ptr: []u8 = actual[0..prior.value];
            const allocated = alloc.realloc(as_fat_ptr, new_size) catch return null;
            ALLOCATION_TABLE.put(alloc, @intFromPtr(allocated.ptr), allocated.len) catch @panic("OOM");
            return @ptrCast(allocated.ptr);
        } else {
            @panic("Call `initCapstone` first.");
        }
    } else {
        return null;
    }
}

fn free(ptr: ?*anyopaque) callconv(.c) void {
    if (ptr == null) {
        // nothing to free
        return;
    }

    if (ALLOCATOR) |alloc| {
        const allocated = ALLOCATION_TABLE.fetchSwapRemove(@intFromPtr(ptr)) orelse @panic("table didn't contain item to be freed");
        const p: [*]u8 = @ptrFromInt(allocated.key);
        const allocated_slice: []u8 = p[0..allocated.value];
        alloc.free(allocated_slice);
    } else {
        @panic("free was called before the allocator exists");
    }
}

extern "C" fn vsnprintf([*c]u8, usize, [*c]const u8, [*c]VaList) callconv(.c) c_int;

/// Inits Capstone to be used with Zig
pub fn initCapstone(alloc: std.mem.Allocator) err.CapstoneError!void {
    return initCapstoneManually(alloc, &malloc, &calloc, &realloc, &free, &vsnprintf);
}

/// Inits Capstone to be used with Zig
/// however, in this option, the user provides all the functions
pub fn initCapstoneManually(
    alloc: std.mem.Allocator,
    malloc_fn: MallocFunction,
    calloc_fn: CallocFunction,
    realloc_fn: ReallocFunction,
    free_fn: FreeFunction,
    vsnprintf_fn: VsnprintfFunction,
) err.CapstoneError!void {
    ALLOCATOR = alloc;
    const sys_mem = cs.cs_opt_mem{
        .malloc = malloc_fn,
        .calloc = calloc_fn,
        .realloc = realloc_fn,
        .free = free_fn,
        .vsnprintf = @ptrCast(vsnprintf_fn),
    };

    const err_return = cs.cs_option(0, cs.CS_OPT_MEM, @intFromPtr(&sys_mem));

    if (err.toError(err_return)) |e| {
        return e;
    }
}
