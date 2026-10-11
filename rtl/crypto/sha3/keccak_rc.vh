// -----------------------------------------------------------------------------
// keccak_rc.vh -- Keccak-f[1600] constants for rtl/crypto/sha3/keccak_f1600.v
//
// GENERATED FILE -- DO NOT EDIT BY HAND.
//   source:    model/sha3.py  (RC, ROTC)
//   generator: scripts/gen_keccak_rc.py
//   regenerate: python scripts/gen_keccak_rc.py
//   verify:     python scripts/gen_keccak_rc.py --check
//
// The model is the single source of truth for these values and is frozen and
// KAT-verified. Editing this header by hand reintroduces exactly the
// transcription bug the generator exists to prevent.
// -----------------------------------------------------------------------------

`ifndef KECCAK_RC_VH
`define KECCAK_RC_VH

// A shared constants header defines more than any single consumer uses:
// keccak_f1600.v may index KECCAK_RC_FLAT by a round counter and never
// reference the individual KECCAK_RCnn, while a differently-structured
// implementation does the reverse. Under -Wall that is 39 UNUSEDPARAM
// warnings and a red lint job, for a header whose whole purpose is to
// offer every form the RTL might want. Scoped off for this file only.
/* verilator lint_off UNUSEDPARAM */

// iota round constants, FIPS 202 sec 3.2.5 -- one 64-bit lane per round.
// Indexed by round number 0..23.
localparam integer KECCAK_ROUNDS = 24;

localparam [63:0] KECCAK_RC00 = 64'h0000000000000001;
localparam [63:0] KECCAK_RC01 = 64'h0000000000008082;
localparam [63:0] KECCAK_RC02 = 64'h800000000000808A;
localparam [63:0] KECCAK_RC03 = 64'h8000000080008000;
localparam [63:0] KECCAK_RC04 = 64'h000000000000808B;
localparam [63:0] KECCAK_RC05 = 64'h0000000080000001;
localparam [63:0] KECCAK_RC06 = 64'h8000000080008081;
localparam [63:0] KECCAK_RC07 = 64'h8000000000008009;
localparam [63:0] KECCAK_RC08 = 64'h000000000000008A;
localparam [63:0] KECCAK_RC09 = 64'h0000000000000088;
localparam [63:0] KECCAK_RC10 = 64'h0000000080008009;
localparam [63:0] KECCAK_RC11 = 64'h000000008000000A;
localparam [63:0] KECCAK_RC12 = 64'h000000008000808B;
localparam [63:0] KECCAK_RC13 = 64'h800000000000008B;
localparam [63:0] KECCAK_RC14 = 64'h8000000000008089;
localparam [63:0] KECCAK_RC15 = 64'h8000000000008003;
localparam [63:0] KECCAK_RC16 = 64'h8000000000008002;
localparam [63:0] KECCAK_RC17 = 64'h8000000000000080;
localparam [63:0] KECCAK_RC18 = 64'h000000000000800A;
localparam [63:0] KECCAK_RC19 = 64'h800000008000000A;
localparam [63:0] KECCAK_RC20 = 64'h8000000080008081;
localparam [63:0] KECCAK_RC21 = 64'h8000000000008080;
localparam [63:0] KECCAK_RC22 = 64'h0000000080000001;
localparam [63:0] KECCAK_RC23 = 64'h8000000080008008;

// Packed form, for indexing by a round counter:
//   wire [63:0] rc = KECCAK_RC_FLAT[64*rnd +: 64];
localparam [1535:0] KECCAK_RC_FLAT = 1536'h8000000080008008000000008000000180000000000080808000000080008081800000008000000A000000000000800A8000000000000080800000000000800280000000000080038000000000008089800000000000008B000000008000808B000000008000000A00000000800080090000000000000088000000000000008A800000000000800980000000800080810000000080000001000000000000808B8000000080008000800000000000808A00000000000080820000000000000001;

// rho rotation offsets, FIPS 202 sec 3.2.2, indexed [x][y].
// Lane index in the state array is x + 5*y.
localparam integer KECCAK_ROT_0_0 =  0;  // lane  0
localparam integer KECCAK_ROT_0_1 = 36;  // lane  5
localparam integer KECCAK_ROT_0_2 =  3;  // lane 10
localparam integer KECCAK_ROT_0_3 = 41;  // lane 15
localparam integer KECCAK_ROT_0_4 = 18;  // lane 20
localparam integer KECCAK_ROT_1_0 =  1;  // lane  1
localparam integer KECCAK_ROT_1_1 = 44;  // lane  6
localparam integer KECCAK_ROT_1_2 = 10;  // lane 11
localparam integer KECCAK_ROT_1_3 = 45;  // lane 16
localparam integer KECCAK_ROT_1_4 =  2;  // lane 21
localparam integer KECCAK_ROT_2_0 = 62;  // lane  2
localparam integer KECCAK_ROT_2_1 =  6;  // lane  7
localparam integer KECCAK_ROT_2_2 = 43;  // lane 12
localparam integer KECCAK_ROT_2_3 = 15;  // lane 17
localparam integer KECCAK_ROT_2_4 = 61;  // lane 22
localparam integer KECCAK_ROT_3_0 = 28;  // lane  3
localparam integer KECCAK_ROT_3_1 = 55;  // lane  8
localparam integer KECCAK_ROT_3_2 = 25;  // lane 13
localparam integer KECCAK_ROT_3_3 = 21;  // lane 18
localparam integer KECCAK_ROT_3_4 = 56;  // lane 23
localparam integer KECCAK_ROT_4_0 = 27;  // lane  4
localparam integer KECCAK_ROT_4_1 = 20;  // lane  9
localparam integer KECCAK_ROT_4_2 = 39;  // lane 14
localparam integer KECCAK_ROT_4_3 =  8;  // lane 19
localparam integer KECCAK_ROT_4_4 = 14;  // lane 24

/* verilator lint_on UNUSEDPARAM */

`endif // KECCAK_RC_VH
