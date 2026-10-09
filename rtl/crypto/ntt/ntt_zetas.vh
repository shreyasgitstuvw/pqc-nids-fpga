// -----------------------------------------------------------------------------
// ntt_zetas.vh -- NTT twiddle factors and constants for ML-KEM-512
//
// GENERATED FILE -- DO NOT EDIT BY HAND.
//   source:     model/mlkem/ntt.py  (ZETAS, INV_N, Q)
//               model/mlkem/pke.py  (GAMMAS)
//   generator:  scripts/gen_zetas.py
//   regenerate: python scripts/gen_zetas.py
//   verify:     python scripts/gen_zetas.py --check
//
// The model is the single source of truth for these values and is frozen and
// KAT-verified. Editing this header by hand reintroduces exactly the
// transcription bug the generator exists to prevent.
// -----------------------------------------------------------------------------

`ifndef NTT_ZETAS_VH
`define NTT_ZETAS_VH

/* verilator lint_off UNUSEDPARAM */

// Field modulus and dimension parameters
localparam [11:0] NTT_Q     = 12'd3329;
localparam integer NTT_N     = 256;
localparam [11:0] NTT_INV_N = 12'd3303; // pow(128, -1, 3329)

// Twiddle factor table ZETAS[k] = 17^bit_rev_7(k) mod 3329 for k = 0..127
localparam [11:0] NTT_ZETA_000 = 12'd1;
localparam [11:0] NTT_ZETA_001 = 12'd1729;
localparam [11:0] NTT_ZETA_002 = 12'd2580;
localparam [11:0] NTT_ZETA_003 = 12'd3289;
localparam [11:0] NTT_ZETA_004 = 12'd2642;
localparam [11:0] NTT_ZETA_005 = 12'd630;
localparam [11:0] NTT_ZETA_006 = 12'd1897;
localparam [11:0] NTT_ZETA_007 = 12'd848;
localparam [11:0] NTT_ZETA_008 = 12'd1062;
localparam [11:0] NTT_ZETA_009 = 12'd1919;
localparam [11:0] NTT_ZETA_010 = 12'd193;
localparam [11:0] NTT_ZETA_011 = 12'd797;
localparam [11:0] NTT_ZETA_012 = 12'd2786;
localparam [11:0] NTT_ZETA_013 = 12'd3260;
localparam [11:0] NTT_ZETA_014 = 12'd569;
localparam [11:0] NTT_ZETA_015 = 12'd1746;
localparam [11:0] NTT_ZETA_016 = 12'd296;
localparam [11:0] NTT_ZETA_017 = 12'd2447;
localparam [11:0] NTT_ZETA_018 = 12'd1339;
localparam [11:0] NTT_ZETA_019 = 12'd1476;
localparam [11:0] NTT_ZETA_020 = 12'd3046;
localparam [11:0] NTT_ZETA_021 = 12'd56;
localparam [11:0] NTT_ZETA_022 = 12'd2240;
localparam [11:0] NTT_ZETA_023 = 12'd1333;
localparam [11:0] NTT_ZETA_024 = 12'd1426;
localparam [11:0] NTT_ZETA_025 = 12'd2094;
localparam [11:0] NTT_ZETA_026 = 12'd535;
localparam [11:0] NTT_ZETA_027 = 12'd2882;
localparam [11:0] NTT_ZETA_028 = 12'd2393;
localparam [11:0] NTT_ZETA_029 = 12'd2879;
localparam [11:0] NTT_ZETA_030 = 12'd1974;
localparam [11:0] NTT_ZETA_031 = 12'd821;
localparam [11:0] NTT_ZETA_032 = 12'd289;
localparam [11:0] NTT_ZETA_033 = 12'd331;
localparam [11:0] NTT_ZETA_034 = 12'd3253;
localparam [11:0] NTT_ZETA_035 = 12'd1756;
localparam [11:0] NTT_ZETA_036 = 12'd1197;
localparam [11:0] NTT_ZETA_037 = 12'd2304;
localparam [11:0] NTT_ZETA_038 = 12'd2277;
localparam [11:0] NTT_ZETA_039 = 12'd2055;
localparam [11:0] NTT_ZETA_040 = 12'd650;
localparam [11:0] NTT_ZETA_041 = 12'd1977;
localparam [11:0] NTT_ZETA_042 = 12'd2513;
localparam [11:0] NTT_ZETA_043 = 12'd632;
localparam [11:0] NTT_ZETA_044 = 12'd2865;
localparam [11:0] NTT_ZETA_045 = 12'd33;
localparam [11:0] NTT_ZETA_046 = 12'd1320;
localparam [11:0] NTT_ZETA_047 = 12'd1915;
localparam [11:0] NTT_ZETA_048 = 12'd2319;
localparam [11:0] NTT_ZETA_049 = 12'd1435;
localparam [11:0] NTT_ZETA_050 = 12'd807;
localparam [11:0] NTT_ZETA_051 = 12'd452;
localparam [11:0] NTT_ZETA_052 = 12'd1438;
localparam [11:0] NTT_ZETA_053 = 12'd2868;
localparam [11:0] NTT_ZETA_054 = 12'd1534;
localparam [11:0] NTT_ZETA_055 = 12'd2402;
localparam [11:0] NTT_ZETA_056 = 12'd2647;
localparam [11:0] NTT_ZETA_057 = 12'd2617;
localparam [11:0] NTT_ZETA_058 = 12'd1481;
localparam [11:0] NTT_ZETA_059 = 12'd648;
localparam [11:0] NTT_ZETA_060 = 12'd2474;
localparam [11:0] NTT_ZETA_061 = 12'd3110;
localparam [11:0] NTT_ZETA_062 = 12'd1227;
localparam [11:0] NTT_ZETA_063 = 12'd910;
localparam [11:0] NTT_ZETA_064 = 12'd17;
localparam [11:0] NTT_ZETA_065 = 12'd2761;
localparam [11:0] NTT_ZETA_066 = 12'd583;
localparam [11:0] NTT_ZETA_067 = 12'd2649;
localparam [11:0] NTT_ZETA_068 = 12'd1637;
localparam [11:0] NTT_ZETA_069 = 12'd723;
localparam [11:0] NTT_ZETA_070 = 12'd2288;
localparam [11:0] NTT_ZETA_071 = 12'd1100;
localparam [11:0] NTT_ZETA_072 = 12'd1409;
localparam [11:0] NTT_ZETA_073 = 12'd2662;
localparam [11:0] NTT_ZETA_074 = 12'd3281;
localparam [11:0] NTT_ZETA_075 = 12'd233;
localparam [11:0] NTT_ZETA_076 = 12'd756;
localparam [11:0] NTT_ZETA_077 = 12'd2156;
localparam [11:0] NTT_ZETA_078 = 12'd3015;
localparam [11:0] NTT_ZETA_079 = 12'd3050;
localparam [11:0] NTT_ZETA_080 = 12'd1703;
localparam [11:0] NTT_ZETA_081 = 12'd1651;
localparam [11:0] NTT_ZETA_082 = 12'd2789;
localparam [11:0] NTT_ZETA_083 = 12'd1789;
localparam [11:0] NTT_ZETA_084 = 12'd1847;
localparam [11:0] NTT_ZETA_085 = 12'd952;
localparam [11:0] NTT_ZETA_086 = 12'd1461;
localparam [11:0] NTT_ZETA_087 = 12'd2687;
localparam [11:0] NTT_ZETA_088 = 12'd939;
localparam [11:0] NTT_ZETA_089 = 12'd2308;
localparam [11:0] NTT_ZETA_090 = 12'd2437;
localparam [11:0] NTT_ZETA_091 = 12'd2388;
localparam [11:0] NTT_ZETA_092 = 12'd733;
localparam [11:0] NTT_ZETA_093 = 12'd2337;
localparam [11:0] NTT_ZETA_094 = 12'd268;
localparam [11:0] NTT_ZETA_095 = 12'd641;
localparam [11:0] NTT_ZETA_096 = 12'd1584;
localparam [11:0] NTT_ZETA_097 = 12'd2298;
localparam [11:0] NTT_ZETA_098 = 12'd2037;
localparam [11:0] NTT_ZETA_099 = 12'd3220;
localparam [11:0] NTT_ZETA_100 = 12'd375;
localparam [11:0] NTT_ZETA_101 = 12'd2549;
localparam [11:0] NTT_ZETA_102 = 12'd2090;
localparam [11:0] NTT_ZETA_103 = 12'd1645;
localparam [11:0] NTT_ZETA_104 = 12'd1063;
localparam [11:0] NTT_ZETA_105 = 12'd319;
localparam [11:0] NTT_ZETA_106 = 12'd2773;
localparam [11:0] NTT_ZETA_107 = 12'd757;
localparam [11:0] NTT_ZETA_108 = 12'd2099;
localparam [11:0] NTT_ZETA_109 = 12'd561;
localparam [11:0] NTT_ZETA_110 = 12'd2466;
localparam [11:0] NTT_ZETA_111 = 12'd2594;
localparam [11:0] NTT_ZETA_112 = 12'd2804;
localparam [11:0] NTT_ZETA_113 = 12'd1092;
localparam [11:0] NTT_ZETA_114 = 12'd403;
localparam [11:0] NTT_ZETA_115 = 12'd1026;
localparam [11:0] NTT_ZETA_116 = 12'd1143;
localparam [11:0] NTT_ZETA_117 = 12'd2150;
localparam [11:0] NTT_ZETA_118 = 12'd2775;
localparam [11:0] NTT_ZETA_119 = 12'd886;
localparam [11:0] NTT_ZETA_120 = 12'd1722;
localparam [11:0] NTT_ZETA_121 = 12'd1212;
localparam [11:0] NTT_ZETA_122 = 12'd1874;
localparam [11:0] NTT_ZETA_123 = 12'd1029;
localparam [11:0] NTT_ZETA_124 = 12'd2110;
localparam [11:0] NTT_ZETA_125 = 12'd2935;
localparam [11:0] NTT_ZETA_126 = 12'd885;
localparam [11:0] NTT_ZETA_127 = 12'd2154;

// Packed form for twiddle ROM / flat indexing:
//   wire [11:0] zeta = NTT_ZETAS_FLAT[12*k +: 12];
localparam [1535:0] NTT_ZETAS_FLAT = 1536'h86A375B7783E4057524BC6BA376AD7866477402193444AF4A229A22318332F5AD513F42766D82A9F5177C947F58FA63028110C9212DD9549859043ABA7F5B53B87376FDAE56736A7BEABC786C2F40E9CD1A6658144C8F02D3665A59247AC901138E4CBC269AA2885C9A39A579625FEB3459E1C432759B90F77B528021B312789D17B928A8078E59004AD6DCCB514B1213357B6B3F959B4221782E5925358C0038BE65C453B98F1286D2239CBCAE231D0C177F426350769276A52CD9A146C1001;

// Base-case multiplication twiddles GAMMAS[i] = 17^(2*bit_rev_7(i)+1) mod 3329 for i = 0..127
localparam [11:0] NTT_GAMMA_000 = 12'd17;
localparam [11:0] NTT_GAMMA_001 = 12'd3312;
localparam [11:0] NTT_GAMMA_002 = 12'd2761;
localparam [11:0] NTT_GAMMA_003 = 12'd568;
localparam [11:0] NTT_GAMMA_004 = 12'd583;
localparam [11:0] NTT_GAMMA_005 = 12'd2746;
localparam [11:0] NTT_GAMMA_006 = 12'd2649;
localparam [11:0] NTT_GAMMA_007 = 12'd680;
localparam [11:0] NTT_GAMMA_008 = 12'd1637;
localparam [11:0] NTT_GAMMA_009 = 12'd1692;
localparam [11:0] NTT_GAMMA_010 = 12'd723;
localparam [11:0] NTT_GAMMA_011 = 12'd2606;
localparam [11:0] NTT_GAMMA_012 = 12'd2288;
localparam [11:0] NTT_GAMMA_013 = 12'd1041;
localparam [11:0] NTT_GAMMA_014 = 12'd1100;
localparam [11:0] NTT_GAMMA_015 = 12'd2229;
localparam [11:0] NTT_GAMMA_016 = 12'd1409;
localparam [11:0] NTT_GAMMA_017 = 12'd1920;
localparam [11:0] NTT_GAMMA_018 = 12'd2662;
localparam [11:0] NTT_GAMMA_019 = 12'd667;
localparam [11:0] NTT_GAMMA_020 = 12'd3281;
localparam [11:0] NTT_GAMMA_021 = 12'd48;
localparam [11:0] NTT_GAMMA_022 = 12'd233;
localparam [11:0] NTT_GAMMA_023 = 12'd3096;
localparam [11:0] NTT_GAMMA_024 = 12'd756;
localparam [11:0] NTT_GAMMA_025 = 12'd2573;
localparam [11:0] NTT_GAMMA_026 = 12'd2156;
localparam [11:0] NTT_GAMMA_027 = 12'd1173;
localparam [11:0] NTT_GAMMA_028 = 12'd3015;
localparam [11:0] NTT_GAMMA_029 = 12'd314;
localparam [11:0] NTT_GAMMA_030 = 12'd3050;
localparam [11:0] NTT_GAMMA_031 = 12'd279;
localparam [11:0] NTT_GAMMA_032 = 12'd1703;
localparam [11:0] NTT_GAMMA_033 = 12'd1626;
localparam [11:0] NTT_GAMMA_034 = 12'd1651;
localparam [11:0] NTT_GAMMA_035 = 12'd1678;
localparam [11:0] NTT_GAMMA_036 = 12'd2789;
localparam [11:0] NTT_GAMMA_037 = 12'd540;
localparam [11:0] NTT_GAMMA_038 = 12'd1789;
localparam [11:0] NTT_GAMMA_039 = 12'd1540;
localparam [11:0] NTT_GAMMA_040 = 12'd1847;
localparam [11:0] NTT_GAMMA_041 = 12'd1482;
localparam [11:0] NTT_GAMMA_042 = 12'd952;
localparam [11:0] NTT_GAMMA_043 = 12'd2377;
localparam [11:0] NTT_GAMMA_044 = 12'd1461;
localparam [11:0] NTT_GAMMA_045 = 12'd1868;
localparam [11:0] NTT_GAMMA_046 = 12'd2687;
localparam [11:0] NTT_GAMMA_047 = 12'd642;
localparam [11:0] NTT_GAMMA_048 = 12'd939;
localparam [11:0] NTT_GAMMA_049 = 12'd2390;
localparam [11:0] NTT_GAMMA_050 = 12'd2308;
localparam [11:0] NTT_GAMMA_051 = 12'd1021;
localparam [11:0] NTT_GAMMA_052 = 12'd2437;
localparam [11:0] NTT_GAMMA_053 = 12'd892;
localparam [11:0] NTT_GAMMA_054 = 12'd2388;
localparam [11:0] NTT_GAMMA_055 = 12'd941;
localparam [11:0] NTT_GAMMA_056 = 12'd733;
localparam [11:0] NTT_GAMMA_057 = 12'd2596;
localparam [11:0] NTT_GAMMA_058 = 12'd2337;
localparam [11:0] NTT_GAMMA_059 = 12'd992;
localparam [11:0] NTT_GAMMA_060 = 12'd268;
localparam [11:0] NTT_GAMMA_061 = 12'd3061;
localparam [11:0] NTT_GAMMA_062 = 12'd641;
localparam [11:0] NTT_GAMMA_063 = 12'd2688;
localparam [11:0] NTT_GAMMA_064 = 12'd1584;
localparam [11:0] NTT_GAMMA_065 = 12'd1745;
localparam [11:0] NTT_GAMMA_066 = 12'd2298;
localparam [11:0] NTT_GAMMA_067 = 12'd1031;
localparam [11:0] NTT_GAMMA_068 = 12'd2037;
localparam [11:0] NTT_GAMMA_069 = 12'd1292;
localparam [11:0] NTT_GAMMA_070 = 12'd3220;
localparam [11:0] NTT_GAMMA_071 = 12'd109;
localparam [11:0] NTT_GAMMA_072 = 12'd375;
localparam [11:0] NTT_GAMMA_073 = 12'd2954;
localparam [11:0] NTT_GAMMA_074 = 12'd2549;
localparam [11:0] NTT_GAMMA_075 = 12'd780;
localparam [11:0] NTT_GAMMA_076 = 12'd2090;
localparam [11:0] NTT_GAMMA_077 = 12'd1239;
localparam [11:0] NTT_GAMMA_078 = 12'd1645;
localparam [11:0] NTT_GAMMA_079 = 12'd1684;
localparam [11:0] NTT_GAMMA_080 = 12'd1063;
localparam [11:0] NTT_GAMMA_081 = 12'd2266;
localparam [11:0] NTT_GAMMA_082 = 12'd319;
localparam [11:0] NTT_GAMMA_083 = 12'd3010;
localparam [11:0] NTT_GAMMA_084 = 12'd2773;
localparam [11:0] NTT_GAMMA_085 = 12'd556;
localparam [11:0] NTT_GAMMA_086 = 12'd757;
localparam [11:0] NTT_GAMMA_087 = 12'd2572;
localparam [11:0] NTT_GAMMA_088 = 12'd2099;
localparam [11:0] NTT_GAMMA_089 = 12'd1230;
localparam [11:0] NTT_GAMMA_090 = 12'd561;
localparam [11:0] NTT_GAMMA_091 = 12'd2768;
localparam [11:0] NTT_GAMMA_092 = 12'd2466;
localparam [11:0] NTT_GAMMA_093 = 12'd863;
localparam [11:0] NTT_GAMMA_094 = 12'd2594;
localparam [11:0] NTT_GAMMA_095 = 12'd735;
localparam [11:0] NTT_GAMMA_096 = 12'd2804;
localparam [11:0] NTT_GAMMA_097 = 12'd525;
localparam [11:0] NTT_GAMMA_098 = 12'd1092;
localparam [11:0] NTT_GAMMA_099 = 12'd2237;
localparam [11:0] NTT_GAMMA_100 = 12'd403;
localparam [11:0] NTT_GAMMA_101 = 12'd2926;
localparam [11:0] NTT_GAMMA_102 = 12'd1026;
localparam [11:0] NTT_GAMMA_103 = 12'd2303;
localparam [11:0] NTT_GAMMA_104 = 12'd1143;
localparam [11:0] NTT_GAMMA_105 = 12'd2186;
localparam [11:0] NTT_GAMMA_106 = 12'd2150;
localparam [11:0] NTT_GAMMA_107 = 12'd1179;
localparam [11:0] NTT_GAMMA_108 = 12'd2775;
localparam [11:0] NTT_GAMMA_109 = 12'd554;
localparam [11:0] NTT_GAMMA_110 = 12'd886;
localparam [11:0] NTT_GAMMA_111 = 12'd2443;
localparam [11:0] NTT_GAMMA_112 = 12'd1722;
localparam [11:0] NTT_GAMMA_113 = 12'd1607;
localparam [11:0] NTT_GAMMA_114 = 12'd1212;
localparam [11:0] NTT_GAMMA_115 = 12'd2117;
localparam [11:0] NTT_GAMMA_116 = 12'd1874;
localparam [11:0] NTT_GAMMA_117 = 12'd1455;
localparam [11:0] NTT_GAMMA_118 = 12'd1029;
localparam [11:0] NTT_GAMMA_119 = 12'd2300;
localparam [11:0] NTT_GAMMA_120 = 12'd2110;
localparam [11:0] NTT_GAMMA_121 = 12'd1219;
localparam [11:0] NTT_GAMMA_122 = 12'd2935;
localparam [11:0] NTT_GAMMA_123 = 12'd394;
localparam [11:0] NTT_GAMMA_124 = 12'd885;
localparam [11:0] NTT_GAMMA_125 = 12'd2444;
localparam [11:0] NTT_GAMMA_126 = 12'd2154;
localparam [11:0] NTT_GAMMA_127 = 12'd1175;

localparam [1535:0] NTT_GAMMAS_FLAT = 1536'h49786A98C37518AB774C383E8FC4055AF7528454BC6476BA98B37622AAD749B86688A4778FF402B6E1938BD44420DAF42DFA2235F9A2AD02314CE833A0C2F522CAD5BC213F8DA42769466D4D782A30C9F5B8A17706DC9450C7F54078FA6D1630A80281BF510C3E0921A242DD3AD95437C9853FD9049563AB282A7F74C5B59493B85CA7376046FD21CAE568E67365A6A7117BEA13ABC749586CA0D2F4C180E9030CD129BA667805818B544C4118F0A2E2D369C6652A8A59ABA247238AC9CF0011;

/* verilator lint_on UNUSEDPARAM */

`endif // NTT_ZETAS_VH
