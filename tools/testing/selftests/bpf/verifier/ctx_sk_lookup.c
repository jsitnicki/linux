{
	"valid 4-byte read from bpf_sk_lookup",
	.insns = {
		/* 4-byte read from family field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, family)),
		/* 4-byte read from protocol field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, protocol)),
		/* 4-byte read from remote_ip4 field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, remote_ip4)),
		/* 4-byte read from remote_ip6 field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, remote_ip6[0])),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, remote_ip6[1])),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, remote_ip6[2])),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, remote_ip6[3])),
		/* 4-byte read from remote_port field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, remote_port)),
		/* 4-byte read from local_ip4 field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, local_ip4)),
		/* 4-byte read from local_ip6 field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, local_ip6[0])),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, local_ip6[1])),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, local_ip6[2])),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, local_ip6[3])),
		/* 4-byte read from local_port field */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, local_port)),
		/* 8-byte read from sk field */
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, sk)),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
/* invalid size reads from a 4-byte field in bpf_sk_lookup */
{
	"invalid 8-byte read from bpf_sk_lookup family field",
	.insns = {
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, family)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 2-byte read from bpf_sk_lookup family field",
	.insns = {
		BPF_LDX_MEM(BPF_H, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, family)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 1-byte read from bpf_sk_lookup family field",
	.insns = {
		BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, family)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
/* invalid size reads from an 8-byte field in bpf_sk_lookup */
{
	"invalid 4-byte read from bpf_sk_lookup sk field",
	.insns = {
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, sk)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 2-byte read from bpf_sk_lookup sk field",
	.insns = {
		BPF_LDX_MEM(BPF_H, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, sk)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 1-byte read from bpf_sk_lookup sk field",
	.insns = {
		BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1,
			    offsetof(struct bpf_sk_lookup, sk)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
/* out of bounds and unaligned reads from bpf_sk_lookup */
{
	"invalid 4-byte read past end of bpf_sk_lookup",
	.insns = {
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
			    sizeof(struct bpf_sk_lookup)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 4-byte unaligned read from bpf_sk_lookup at odd offset",
	.insns = {
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 1),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 4-byte unaligned read from bpf_sk_lookup at even offset",
	.insns = {
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 2),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
/* writes to and out of bounds of bpf_sk_lookup */
{
	"invalid 8-byte write to bpf_sk_lookup",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0xcafe4a11U),
		BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 4-byte write to bpf_sk_lookup",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0xcafe4a11U),
		BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 2-byte write to bpf_sk_lookup",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0xcafe4a11U),
		BPF_STX_MEM(BPF_H, BPF_REG_1, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 1-byte write to bpf_sk_lookup",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0xcafe4a11U),
		BPF_STX_MEM(BPF_B, BPF_REG_1, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
{
	"invalid 4-byte write past end of bpf_sk_lookup",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0xcafe4a11U),
		BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_0,
			    sizeof(struct bpf_sk_lookup)),
		BPF_EXIT_INSN(),
	},
	.errstr = "invalid bpf_context access",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SK_LOOKUP,
	.expected_attach_type = BPF_SK_LOOKUP,
},
