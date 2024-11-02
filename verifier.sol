// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x22723b8e669d67a66c30cf257c855825f8bcab606e855dff928c43427e2b31ce), uint256(0x221cb9e57e2aa2f283e1812e3288d5020db63e48bdadb923dfa27dbb4a1ed3b5));
        vk.beta = Pairing.G2Point([uint256(0x1c93fde7b08dcba214ac7cdc7821479537e355f2b8da090d348a8dbcc1b3b88d), uint256(0x19e44db916356373e36a29ce5e675c4d2a077c03615ee5796019103814266c56)], [uint256(0x2629023b7d968313ecefbc93a41f69fcf1362bf6bf10dae290ef9f9ae647db8b), uint256(0x1ff68c6fdf859f406e20b4e02b5e2f7b7272cf935713564cd691f353b305ea85)]);
        vk.gamma = Pairing.G2Point([uint256(0x2cedfeacd3664e7e276569f77e7e081528f3d45424afe40f47c9da6ab6e2ec68), uint256(0x1dd249b75cb2fad53f4259cb62b5c326af7ace709b770164fb5f4e309da144fd)], [uint256(0x05e15be8be8df5bee61c8e9d1a1ad638d0cbc5637c9160728c97cb7f7eecbf0f), uint256(0x2eb73f48aab427af21cabd3c147f6a6aaa89d3a16464398f79195c4004599315)]);
        vk.delta = Pairing.G2Point([uint256(0x15b328bf101a71df3173ad415a46dee21c7c885b8419b71f150acd8bea5410a3), uint256(0x0a9688b22a5840fbb97e9a9a6955f03c2d10a4c098e51abf30464ead00a23c7c)], [uint256(0x18114305cae24b22be891d79e90d7465e2053298faf4e558447636ce46614c94), uint256(0x1c47c0cab070d173334d0869c50e85eb1317c01cf534f7d720b718141c3c8584)]);
        vk.gamma_abc = new Pairing.G1Point[](34);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x196d16098b700b224adaf040ed818751ca494786ed053d822a0345b10bd5c224), uint256(0x2b71e99573f0ad059862ef89f6cf815a3e39ac858e310c31624011e070c1119a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x046384c62587d3673378744920131e1ea08f2240908e0283301c9a56ca445e8d), uint256(0x107d1aa68ef57a3122674dbbdf46c1366cb761932712b0ff0e2692d76edc4b7f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1f64ffe4f31d1c69156a2585a174c147b8e92dda2967c7f7d88621e08f014416), uint256(0x08df048ca64c5b062c71703e76b35cb9f2eda9e070363b7fc6e0d5cec6815625));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x15867f73a891926d44f62274a4d511f1debf65d3d27c32eec17e247fa7a0d7fd), uint256(0x1bba7bb67cf2856d53acef2eb9a57c0174e9df2eadf102fe6cea44c3d2cf850a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2ef8f731d92b7ddbc78dcde71ddcccc90154bbeda097210d346e442e3256ec60), uint256(0x1fd23f5c2780d313055b10aec6c458def5795ee5a14a44e7d3f25c3a7982251e));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2eb0c176cbb57461903bd909bb8f44381eeba1f0f35f75c627de42eab770d18a), uint256(0x21c046e05f26bcbb31bcc7156d2ea93761ad19befeca3d8c3443d2d567b0c378));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0000529e54334121ad98a668167f03f1858a24f58d22c30cd72d3f8b1bafa974), uint256(0x083dfb41dc44a60921318b13fc27caf80207797ab447da0fa751b8858264e4ce));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x154fe4650860c66c0a0b102c603d279a7322ea524cf481108e75f2df390a16e0), uint256(0x14cf7613fba35e770b44f6ceb104a816b27f8e5d0dcc4b12d1c4dbbbd6298838));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1dcbfbc878549eb9c70c3ff3e2c9cce53fdb62a6ab0dc2753bdc3873162a3435), uint256(0x1f9279d78a0b51dbc7b4fa622e00c76ee32f144edadaa4d7f295eb2c5099fd25));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0f120a4b4de707db69d47f1f64bd0ce806c433731021f41d50f3c9b599eb0a4c), uint256(0x3018afd37db80f6c90ef69483af30954c890e960af2d9883b5bd90b1dd589462));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1044f25b2e7be657e8e71d32072fb182477fcc5076afb2f21c532204d32e2211), uint256(0x29e5c46f51321fd2606621220d7ed6e4bfe8cd06581de9083c3a37dd8846369e));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1def5422cc2303cce2af99ed983aa52cb61eb55d6b0dedd6ef01b9b132315911), uint256(0x1641824d08cd2efb19ea053e0f1113822ffa1d6740f672d2b0a156b6b862ba70));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1e0862561906925ad78f7b2d607e1f7f09187064f5c99a6f58cc239937f1521f), uint256(0x303e888291637a1d7242c2e7d19a081b2cb49bad9205490de168752b82f49c42));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1077d355e76ff0643149ac6a01decb1aba66c8e234fb7ed91ac5a60531e567ac), uint256(0x13e97b63e3adb9a2b18eb39a6165cb77dc9ec6ddf29a520ef439b7b0791c2bdf));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2283c6294e29c38190b7fe4bce3010c2254b5283b28321525c52a2a1ab1a611f), uint256(0x0a6bfef76dd8610cb3aa4ad7c4e23aa6ae0ab88abadbc2212186fd868c4843fd));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x13f7711da4794db020378897719b6ac789dc0682dd2eb78a7a8beffcddb3f270), uint256(0x17777c95b11eecce9675937c976ce87eb11061cc391594dc0b9c8030e97bcdde));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2e106c12b6e61b29058edaa64031c81a642b9128b8cecb57a47b7ab893ac507a), uint256(0x292a63b6333819793290bc7a07488b583dd78a1d2e627a3ce83d03464594c725));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1b469e8bc6ded90902444e215d632c4c8352ed05306c853463f31c1f5e1b4171), uint256(0x0fdcf7405bea75245d73f096222c37790b660bb87ebd0e27a2e1b996fccef3cc));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x13fd4125717e776006329a90bb751d352bbd0e374b140b7ab69577a4aa34cf86), uint256(0x20a9d6b93eeb8d33d15bc560e0ff5df2e21d51e2ab9f64bc06e182d324ac2b4c));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x01aca422b45c1d97eb68345cd6967a3aa05f5b68f9f9973b87ee792fdbd180a9), uint256(0x08eda69302449e858da37df4c463ddf69567aee4844c5f82bc841d48d39e8675));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x250184bbd7caa96c5d96631ab68270fc9ecb966e153c43bf0c6a3b763fe1ebe6), uint256(0x0ab991c7db23102bd030dc30d2055f441432aa50fe431ac9951301d8cdfe09f3));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x18558c9daac5a1eec762a28041f1f13ff4b403a7129473247096b57159852d5b), uint256(0x191abcbf8e0da68119d7e5eb82e66190a47b09b6d635c7b402c7f8cc6b425138));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0a9da8ece16be9c7c9cd626ba5f6bac1b7a322e5786ab2ea85a281753d91858d), uint256(0x16bb4719bad76c541e4ef1e1da83a5fb9b23862565bb5b5064223b9c668ddd19));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1535ef03025a556351d4729ac15755dd4f0d9337472ecd15ae57feec9ce9d2de), uint256(0x295baf1a741bc326ed34cfb38f8d00a42b229948091c3f666db4b5c97e6d5e27));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x19a0489e379b082ee778513f9aaeeb6c5839769445b856bd122ed54898d3b083), uint256(0x2b2b7bcacd586f654ba10f2bc9523f4cd8c0b329d253090e43aa842afc176305));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0ac955b2ae7542b64327c917a574eed4fadc842e6e2d2b69aab9a7310c36021f), uint256(0x2584e99ec3bee365e9862e0b269f4fedcffa952c58104ee442658601df745328));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2a04135ca203351aba793b029a60962fc7a7fce124ab6f0637dfc85425f923e2), uint256(0x2e8564d24429568fcce4bbb9f5ff36a8e5fbb638a4b4ab772b4daa622d3a8077));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x24df468ccb0c6ee031e3a791d42a429cdeb3f48e5eef1131e6a728256e8d4edb), uint256(0x1b48f097b2e685bf930cd1bf49db30305bd7a39eec1bda40b6067609c56a997b));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x16052e71c1cdf0a236c95924f3c59e0d20c7e92d3106368c48b4aa5261bc6e7b), uint256(0x171f757f916997e1924d3bcecc0cdfe895ae95ee2a13e4f5d8610886ca1f325f));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x18aed3cfad1ba412e7b5d3d8c35b5cc4065c03a9dd90ea4fe530f80e1c01ab85), uint256(0x08b91e83c13b20b693e57b98bab9008ac51135731b43f0e0f5c245462ab8b7fb));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x225c05feaca0c02997fd3f3e64d510a793032bed0518d08f696a2ee910f318fe), uint256(0x04d38ad7a6ab25f4ee6ae72cfd7229d2665ea7c2dff2f73bce1a92e2ae9b3bf9));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0b560e81e2026879123347a28a6a106f12e7831efd72478d6ed37911a26baa77), uint256(0x1ac0be2de7875c44cf7ebad1b2cc0df8af6b209a0947d20e5e225922e100a13a));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0f964c293550d1ffcac3e25549825cdaa15ffdcffe1eeaa2fc6aba3285a9e4fc), uint256(0x1c458b5cbfd7069e6dabce1e3238d804c73197419bbf63c4d1110ac3af0143e9));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x10e95c6fe677ffa9e3a70be24793a47883663b6e3563428fac06f7a65e7edbd9), uint256(0x028e5300c7544497fab91c19ae42d36ac1177bb3416930643ff333a1d2af4c96));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[33] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](33);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
