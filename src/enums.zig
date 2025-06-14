const std = @import("std");
const cs = @import("capstone-c");

pub const Arch = enum(cs.cs_arch) {
    ARM = 0,
    ARM64,
    MIPS,
    X86,
    PPC,
    SPARC,
    SYSZ,
    XCORE,
    M68K,
    TMS320C64X,
    M680X,
    EVM,
    MOS65XX,
    WASM,
    BPF,
    RISCV,
    SH,
    TRICORE,
    MAX = 18,
    ALL = 65535,
};

/// This is a workaround for msvc ABI, the translate_c translate's enum as c_int intead of c_uint.
pub const cs_mode = c_uint;
pub const Mode = enum(cs_mode) {
    LITTLE_ENDIAN = 0,
    BPF_EXTENDED = 1,
    @"16" = 2,
    @"32" = 4,
    @"64" = 8,
    THUMB = 16,
    MCLASS = 32,
    V8 = 64,
    MIPS2 = 128,
    BIG_ENDIAN = 2147483648,
    M680X_6811 = 256,
    M680X_CPU12 = 512,
    M680X_HCS08 = 1024,
    MOS65XX_65816_LONG_MX = 96,

    pub const ARM: cs_mode = @intFromEnum(Mode.LITTLE_ENDIAN);
    pub const BPF_CLASSIC: cs_mode = @intFromEnum(Mode.LITTLE_ENDIAN);

    pub const RISCV32: cs_mode = @intFromEnum(Mode.BPF_EXTENDED);

    pub const M68K_000: cs_mode = @intFromEnum(Mode.@"16");
    pub const M680X_6301: cs_mode = @intFromEnum(Mode.@"16");
    pub const RISCV64: cs_mode = @intFromEnum(Mode.@"16");
    pub const MOS65XX_6502: cs_mode = @intFromEnum(Mode.@"16");
    pub const SH2: cs_mode = @intFromEnum(Mode.@"16");
    pub const TRICORE_110: cs_mode = @intFromEnum(Mode.@"16");

    pub const M68K_010: cs_mode = @intFromEnum(Mode.@"32");
    pub const MIPS32: cs_mode = @intFromEnum(Mode.@"32");
    pub const M680X_6309: cs_mode = @intFromEnum(Mode.@"32");
    pub const RISCVC: cs_mode = @intFromEnum(Mode.@"32");
    pub const MOS65XX_65C02: cs_mode = @intFromEnum(Mode.@"32");
    pub const SH2A: cs_mode = @intFromEnum(Mode.@"32");
    pub const TRICORE_120: cs_mode = @intFromEnum(Mode.@"32");

    pub const M68K_020: cs_mode = @intFromEnum(Mode.@"64");
    pub const MIPS64: cs_mode = @intFromEnum(Mode.@"64");
    pub const M680X_6800: cs_mode = @intFromEnum(Mode.@"64");
    pub const MOS65XX_W65C02: cs_mode = @intFromEnum(Mode.@"64");
    pub const SH3: cs_mode = @intFromEnum(Mode.@"64");
    pub const TRICORE_130: cs_mode = @intFromEnum(Mode.@"64");

    pub const MICRO: cs_mode = @intFromEnum(Mode.THUMB);
    pub const V9: cs_mode = @intFromEnum(Mode.THUMB);
    pub const QPX: cs_mode = @intFromEnum(Mode.THUMB);
    pub const M68K_030: cs_mode = @intFromEnum(Mode.THUMB);
    pub const M680X_6801: cs_mode = @intFromEnum(Mode.THUMB);
    pub const MOS65XX_65816: cs_mode = @intFromEnum(Mode.THUMB);
    pub const SH4: cs_mode = @intFromEnum(Mode.THUMB);
    pub const TRICORE_131: cs_mode = @intFromEnum(Mode.THUMB);

    pub const MIPS3: cs_mode = @intFromEnum(Mode.MCLASS);
    pub const SPE: cs_mode = @intFromEnum(Mode.MCLASS);
    pub const M68K_040: cs_mode = @intFromEnum(Mode.MCLASS);
    pub const M680X_6805: cs_mode = @intFromEnum(Mode.MCLASS);
    pub const MOS65XX_65816_LONG_M: cs_mode = @intFromEnum(Mode.MCLASS);
    pub const SH4A: cs_mode = @intFromEnum(Mode.MCLASS);
    pub const TRICORE_160: cs_mode = @intFromEnum(Mode.MCLASS);

    pub const MIPS32R6: cs_mode = @intFromEnum(Mode.V8);
    pub const BOOKE: cs_mode = @intFromEnum(Mode.V8);
    pub const M68K_060: cs_mode = @intFromEnum(Mode.V8);
    pub const M680X_6808: cs_mode = @intFromEnum(Mode.V8);
    pub const MOS65XX_65816_LONG_X: cs_mode = @intFromEnum(Mode.V8);
    pub const SHFPU: cs_mode = @intFromEnum(Mode.V8);
    pub const TRICORE_161: cs_mode = @intFromEnum(Mode.V8);

    pub const PS: cs_mode = @intFromEnum(Mode.MIPS2);
    pub const M680X_6809: cs_mode = @intFromEnum(Mode.MIPS2);
    pub const SHDSP: cs_mode = @intFromEnum(Mode.MIPS2);
    pub const TRICORE_162: cs_mode = @intFromEnum(Mode.MIPS2);

    const Self = @This();

    pub fn extend(self: Self, others: []const Self) cs_mode {
        var result: cs_mode = @intFromEnum(self);
        for (others) |other| {
            result |= @intFromEnum(other);
        }
        return result;
    }

    pub fn extendInt(self: Self, others: []const cs_mode) cs_mode {
        var result: cs_mode = @intFromEnum(self);
        for (others) |other| {
            result |= other;
        }
        return result;
    }

    inline fn getInt(comptime literal: @TypeOf(.enum_literal)) ?cs_mode {
        const self_type_info = @typeInfo(Self);
        const self_enum = self_type_info.@"enum";
        const literal_name = @tagName(literal);

        return comptime blk: {
            for (self_enum.fields) |field| {
                if (std.mem.eql(u8, literal_name, field.name)) {
                    break :blk field.value;
                }
            }

            for (self_enum.decls) |decl| {
                if (std.mem.eql(u8, literal_name, decl.name)) {
                    break :blk @field(Self, decl.name);
                }
            }

            break :blk null;
        };
    }

    pub fn extendComptime(comptime a: anytype, comptime b: anytype) cs_mode {
        const a_type_info = @typeInfo(@TypeOf(a));
        const b_type_info = @typeInfo(@TypeOf(b));

        var result: cs_mode = 0;
        if (a_type_info == .int or a_type_info == .comptime_int) {
            result = a;
        } else if (a_type_info == .enum_literal) {
            result = getInt(a) orelse @compileError("'" ++ @tagName(a) ++ "' is not valid `Mode` enum literal");
        } else {
            @compileError("Not valid type, expected `a` to be an int or an enum_literal found: '" ++ @typeName(@TypeOf(a)) ++ "'");
        }

        if (b_type_info == .int or b_type_info == .comptime_int) {
            result |= b;
        } else if (b_type_info == .enum_literal) {
            result |= getInt(b) orelse @compileError("'" ++ @tagName(b) ++ "' is not valid `Mode` enum literal");
        } else {
            @compileError("Not valid type, expected `b` to be an int or an enum_literal found: '" ++ @typeName(@TypeOf(b)) ++ "'");
        }

        return result;
    }

    pub fn from(comptime literal: @TypeOf(.enum_literal)) cs_mode {
        return getInt(literal) orelse @compileError("'" ++ @tagName(literal) ++ "' is not valid `Mode` enum literal");
    }
};

pub const Type = enum(cs.cs_opt_type) {
    INVALID,
    SYNTAX,
    DETAIL,
    MODE,
    MEM,
    SKIPDATA,
    SKIPDATA_SETUP,
    MNEMONIC,
    UNSIGNED,
    NO_BRANCH_OFFSET,
};

pub const Syntax = enum(cs.cs_opt_value) {
    DEFAULT = 0,
    INTEL,
    ATT,
    NOREGNAME,
    MASM,
    MOTOROLA,
};
