pub const OpMem = @import("op_mem.zig").OpMem;
pub const OpType = @import("op_type.zig").OpType;
pub const Instruction = @import("instruction.zig").Instruction;
pub const Operand = @import("operand.zig").Operand;
pub const Condition = @import("condition.zig").Condition;
pub const Funit = @import("funit.zig").Funit;

pub const Arch = extern struct {
    op_count: u8,
    operands: [8]Operand,
    condition: Condition,
    funit: Funit,
    parallel: c_uint,
};
