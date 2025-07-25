pub const OpMem = @import("op_mem.zig").OpMem;
pub const OpType = @import("op_type.zig").OpType;
pub const Register = @import("register.zig").Register;
pub const Instruction = @import("instruction.zig").Instruction;
pub const Operand = @import("operand.zig").Operand;

pub const Arch = extern struct {
    op_count: u8,
    operands: [10]Operand,
};
