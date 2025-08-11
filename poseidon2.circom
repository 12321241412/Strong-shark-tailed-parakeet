pragma circom 2.1.6;

// 参数配置 (n,t,d) = (256,3,5)
include "poseidon2_params.circom"; // 轮常数和MDS矩阵

template FullRound(round_index) {
    signal input in[3];
    signal output out[3];
    
    // ARK阶段
    signal ark[3];
    ark[0] <== in[0] + RC[round_index][0];
    ark[1] <== in[1] + RC[round_index][1];
    ark[2] <== in[2] + RC[round_index][2];
    
    // S-box (x^5)
    signal sbox[3];
    sbox[0] <== ark[0] * ark[0] * ark[0] * ark[0] * ark[0]; // x^5
    sbox[1] <== ark[1] * ark[1] * ark[1] * ark[1] * ark[1];
    sbox[2] <== ark[2] * ark[2] * ark[2] * ark[2] * ark[2];
    
    // MDS矩阵乘法
    out[0] <== MDS[0][0]*sbox[0] + MDS[0][1]*sbox[1] + MDS[0][2]*sbox[2];
    out[1] <== MDS[1][0]*sbox[0] + MDS[1][1]*sbox[1] + MDS[1][2]*sbox[2];
    out[2] <== MDS[2][0]*sbox[0] + MDS[2][1]*sbox[1] + MDS[2][2]*sbox[2];
}

template PartialRound(round_index) {
    signal input in[3];
    signal output out[3];
    
    // ARK阶段（仅第一个元素加常数）
    signal ark[3];
    ark[0] <== in[0] + RC[round_index][0];
    ark[1] <== in[1];
    ark[2] <== in[2];
    
    // S-box（仅第一个元素）
    signal sbox[3];
    sbox[0] <== ark[0] * ark[0] * ark[0] * ark[0] * ark[0];
    sbox[1] <== ark[1];
    sbox[2] <== ark[2];
    
    // MDS矩阵乘法
    out[0] <== MDS[0][0]*sbox[0] + MDS[0][1]*sbox[1] + MDS[0][2]*sbox[2];
    out[1] <== MDS[1][0]*sbox[0] + MDS[1][1]*sbox[1] + MDS[1][2]*sbox[2];
    out[2] <== MDS[2][0]*sbox[0] + MDS[2][1]*sbox[1] + MDS[2][2]*sbox[2];
}

template Poseidon2() {
    signal input in0;  // 隐私输入1
    signal input in1;  // 隐私输入2
    signal output out; // 公开哈希值
    
    // 初始化状态 [in0, in1, 0]
    signal state[3];
    state[0] <== in0;
    state[1] <== in1;
    state[2] <== 0;
    
    // 轮次结构：4全轮 + 56部分轮 + 4全轮
    component rounds[64];
    for (var i = 0; i < 64; i++) {
        if (i < 4 || i >= 60) {
            rounds[i] = FullRound(i);
        } else {
            rounds[i] = PartialRound(i);
        }
        
        // 连接状态
        if (i == 0) {
            rounds[i].in[0] <== state[0];
            rounds[i].in[1] <== state[1];
            rounds[i].in[2] <== state[2];
        } else {
            rounds[i].in[0] <== rounds[i-1].out[0];
            rounds[i].in[1] <== rounds[i-1].out[1];
            rounds[i].in[2] <== rounds[i-1].out[2];
        }
    }
    
    // 输出第一个状态元素
    out <== rounds[63].out[0];
}

component main {public [out]} = Poseidon2();