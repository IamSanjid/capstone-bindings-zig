const Instruction = @import("instruction.zig").Instruction;
const OpMem = @import("op_mem.zig").OpMem;
const OpType = @import("op_type.zig").OpType;
const AddressMode = @import("address_mode.zig").AddressMode;
const BrDisp = extern struct { disp: i32, disp_size: u8 };

pub const Operand = extern struct {
    instruction: Instruction,
    mem: OpMem,
    br_disp: BrDisp,
    type: OpType,
    address_mode: AddressMode,
};
