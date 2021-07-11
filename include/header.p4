const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
#define MAX_HDRS 5
#define MAX_KEYS 3000
#define MAX_PACKET_KEYS 3000
#define MAX_HOPS 9

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> hdrChecksum;
}

header srcRoute_t {
    bit<7>    bos;
    bit<9>   port;
}


header agg_t {

    bit<8>     id;
    bit<8>     time_flag;
    bit<32>    num;// worker_sum
    bit<32>    agglen;
    bit<48>    ingress_time;
    bit<48>    egress_time;
    
    // bit<32>    value1;
    // bit<32>    value2;
    // bit<32>    value3;
    // bit<32>    value4;
    bit<32> value1;
    bit<32> value2;
    bit<32> value3;
    bit<32> value4;
    bit<32> value5;
    bit<32> value6;
    bit<32> value7;
    bit<32> value8;
    bit<32> value9;
    bit<32> value10;
    bit<32> value11;
    bit<32> value12;
    bit<32> value13;
    bit<32> value14;
    bit<32> value15;
    bit<32> value16;
    bit<32> value17;
    bit<32> value18;
    bit<32> value19;
    bit<32> value20;
    bit<32> value21;
    bit<32> value22;
    bit<32> value23;
    bit<32> value24;
    bit<32> value25;
    bit<32> value26;
    bit<32> value27;
    bit<32> value28;
    bit<32> value29;
    bit<32> value30;
    bit<32> value31;
    bit<32> value32;
    bit<32> value33;
    bit<32> value34;
    bit<32> value35;
    bit<32> value36;
    bit<32> value37;
    bit<32> value38;
    bit<32> value39;
    bit<32> value40;
    bit<32> value41;
    bit<32> value42;
    bit<32> value43;
    bit<32> value44;
    bit<32> value45;
    bit<32> value46;
    bit<32> value47;
    bit<32> value48;
    bit<32> value49;
    bit<32> value50;
    bit<32> value51;
    bit<32> value52;
    bit<32> value53;
    bit<32> value54;
    bit<32> value55;
    bit<32> value56;
    bit<32> value57;
    bit<32> value58;
    bit<32> value59;
    bit<32> value60;
    bit<32> value61;
    bit<32> value62;
    bit<32> value63;
    bit<32> value64;
    bit<32> value65;
    bit<32> value66;
    bit<32> value67;
    bit<32> value68;
    bit<32> value69;
    bit<32> value70;
    bit<32> value71;
    bit<32> value72;
    bit<32> value73;
    bit<32> value74;
    bit<32> value75;
    bit<32> value76;
    bit<32> value77;
    bit<32> value78;
    bit<32> value79;
    bit<32> value80;
    bit<32> value81;
    bit<32> value82;
    bit<32> value83;
    bit<32> value84;
    bit<32> value85;
    bit<32> value86;
    bit<32> value87;
    bit<32> value88;
    bit<32> value89;
    bit<32> value90;
    bit<32> value91;
    bit<32> value92;
    bit<32> value93;
    bit<32> value94;
    bit<32> value95;
    bit<32> value96;
    bit<32> value97;
    bit<32> value98;
    bit<32> value99;
    bit<32> value100;
    bit<32> value101;
    bit<32> value102;
    bit<32> value103;
    bit<32> value104;
    bit<32> value105;
    bit<32> value106;
    bit<32> value107;
    bit<32> value108;
    bit<32> value109;
    bit<32> value110;
    bit<32> value111;
    bit<32> value112;
    bit<32> value113;
    bit<32> value114;
    bit<32> value115;
    bit<32> value116;
    bit<32> value117;
    bit<32> value118;
    bit<32> value119;
    bit<32> value120;
    bit<32> value121;
    bit<32> value122;
    bit<32> value123;
    bit<32> value124;
    bit<32> value125;
    bit<32> value126;
    bit<32> value127;
    bit<32> value128;
    bit<32> value129;
    bit<32> value130;
    bit<32> value131;
    bit<32> value132;
    bit<32> value133;
    bit<32> value134;
    bit<32> value135;
    bit<32> value136;
    bit<32> value137;
    bit<32> value138;
    bit<32> value139;
    bit<32> value140;
    bit<32> value141;
    bit<32> value142;
    bit<32> value143;
    bit<32> value144;
    bit<32> value145;
    bit<32> value146;
    bit<32> value147;
    bit<32> value148;
    bit<32> value149;
    bit<32> value150;
    bit<32> value151;
    bit<32> value152;
    bit<32> value153;
    bit<32> value154;
    bit<32> value155;
    bit<32> value156;
    bit<32> value157;
    bit<32> value158;
    bit<32> value159;
    bit<32> value160;
    bit<32> value161;
    bit<32> value162;
    bit<32> value163;
    bit<32> value164;
    bit<32> value165;
    bit<32> value166;
    bit<32> value167;
    bit<32> value168;
    bit<32> value169;
    bit<32> value170;
    bit<32> value171;
    bit<32> value172;
    bit<32> value173;
    bit<32> value174;
    bit<32> value175;
    bit<32> value176;
    bit<32> value177;
    bit<32> value178;
    bit<32> value179;
    bit<32> value180;
    bit<32> value181;
    bit<32> value182;
    bit<32> value183;
    bit<32> value184;
    bit<32> value185;
    bit<32> value186;
    bit<32> value187;
    bit<32> value188;
    bit<32> value189;
    bit<32> value190;
    bit<32> value191;
    bit<32> value192;
    bit<32> value193;
    bit<32> value194;
    bit<32> value195;
    bit<32> value196;
    bit<32> value197;
    bit<32> value198;
    bit<32> value199;
    bit<32> value200;
    bit<32> value201;
    bit<32> value202;
    bit<32> value203;
    bit<32> value204;
    bit<32> value205;
    bit<32> value206;
    bit<32> value207;
    bit<32> value208;
    bit<32> value209;
    bit<32> value210;
    bit<32> value211;
    bit<32> value212;
    bit<32> value213;
    bit<32> value214;
    bit<32> value215;
    bit<32> value216;
    bit<32> value217;
    bit<32> value218;
    bit<32> value219;
    bit<32> value220;
    bit<32> value221;
    bit<32> value222;
    bit<32> value223;
    bit<32> value224;
    bit<32> value225;
    bit<32> value226;
    bit<32> value227;
    bit<32> value228;
    bit<32> value229;
    bit<32> value230;
    bit<32> value231;
    bit<32> value232;
    bit<32> value233;
    bit<32> value234;
    bit<32> value235;
    bit<32> value236;
    bit<32> value237;
    bit<32> value238;
    bit<32> value239;
    bit<32> value240;
    bit<32> value241;
    bit<32> value242;
    bit<32> value243;
    bit<32> value244;
    bit<32> value245;
    bit<32> value246;
    bit<32> value247;
    bit<32> value248;
    bit<32> value249;
    bit<32> value250;
    bit<32> value251;
    bit<32> value252;
    bit<32> value253;
    bit<32> value254;
    bit<32> value255;
    bit<32> value256;
    bit<32> value257;
    bit<32> value258;
    bit<32> value259;
    bit<32> value260;
    bit<32> value261;
    bit<32> value262;
    bit<32> value263;
    bit<32> value264;
    bit<32> value265;
    bit<32> value266;
    bit<32> value267;
    bit<32> value268;
    bit<32> value269;
    bit<32> value270;
    bit<32> value271;
    bit<32> value272;
    bit<32> value273;
    bit<32> value274;
    bit<32> value275;
    bit<32> value276;
    bit<32> value277;
    bit<32> value278;
    bit<32> value279;
    bit<32> value280;
    bit<32> value281;
    bit<32> value282;
    bit<32> value283;
    bit<32> value284;
    bit<32> value285;
    bit<32> value286;
    bit<32> value287;
    bit<32> value288;
    bit<32> value289;
    bit<32> value290;
    bit<32> value291;
    bit<32> value292;
    bit<32> value293;
    bit<32> value294;
    bit<32> value295;
    bit<32> value296;
    bit<32> value297;
    bit<32> value298;
    bit<32> value299;
    bit<32> value300;
    bit<32> value301;
    bit<32> value302;
    bit<32> value303;
    bit<32> value304;
    bit<32> value305;
    bit<32> value306;
    bit<32> value307;
    bit<32> value308;
    bit<32> value309;
    bit<32> value310;
    bit<32> value311;
    bit<32> value312;
    bit<32> value313;
    bit<32> value314;
    bit<32> value315;
    bit<32> value316;
    bit<32> value317;
    bit<32> value318;
    bit<32> value319;
    bit<32> value320;
    bit<32> value321;
    bit<32> value322;
    bit<32> value323;
    bit<32> value324;
    bit<32> value325;
    bit<32> value326;
    bit<32> value327;
    bit<32> value328;
    bit<32> value329;
    bit<32> value330;
    bit<32> value331;
    bit<32> value332;
    bit<32> value333;
    bit<32> value334;
    bit<32> value335;
    bit<32> value336;
    bit<32> value337;
    bit<32> value338;
    bit<32> value339;
    bit<32> value340;



}
struct metadata {
    /* empty */
}



struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t           udp;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    agg_t       agg;  
}
