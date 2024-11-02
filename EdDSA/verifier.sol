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
        vk.alpha = Pairing.G1Point(uint256(0x2fbff019b6dd698ac789599f116402b4ed7ba2c849ff1dfc782de616a70ab234), uint256(0x1a71a9436dec7421c63755e4df6bda3e96296e98ad47a4da096dd29eb7e55ef8));
        vk.beta = Pairing.G2Point([uint256(0x30475b8e15bfe34a05e216cdb5516927739eb2bff6cae8cbd3eac176619d954a), uint256(0x2fcddbad423f3393406dbd0b4ec5166e334643c6d62f002503067e106a2c545d)], [uint256(0x2c06414b30bc7348dc87321ada78ce43dd9915056b6dc2a4f42289925b627bbc), uint256(0x1f8d8a0eda413a64e5a562f30be85cdae8cb46acbb09f5090d4efe006819d843)]);
        vk.gamma = Pairing.G2Point([uint256(0x2f968cd71f87f4436181edd2910cc2c4f7212a05eee732a817b9466bc7e6a9ee), uint256(0x1d123791ab66e2f888d6c04917ec232fdc9d1f0a9a7a5c9f8aef1b417c13c3e5)], [uint256(0x076c4e97f6231697e64956cc6b4eca2f268e6dc49e934b608d004af2c6d6fc35), uint256(0x26a9f10f5f803441b2996795cf9e91818e74adb1d77ea1c47264ca5d7611d8e8)]);
        vk.delta = Pairing.G2Point([uint256(0x024a239d5870f955921b52b4060d2dca3899ae1559680d04937b793516561632), uint256(0x2889824b13d864487234c65315bef478edf158fc31dec1a35f77bf6d5cb30edd)], [uint256(0x24936770ebba9d7257876f0d7bf59a47b3147b92bbcd6ce10538fa6a664a97a2), uint256(0x16eddc8d1560f3382d9bd467c0b644a6c21a43df271dfb2f226dcd32e42592c8)]);
        vk.gamma_abc = new Pairing.G1Point[](34);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x099a22f6dd47908e3181edc5be101fb68a1df031929746425c0d06bf59e3884a), uint256(0x0aa656141ac8cda65b84064f82bd3132d0939d0e065a87d1149fb3c4a92f7219));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0fce301bc72a10ca8e4acd8dec8c3692b4af3dc534b4eceb1b06f69a5af2f9f0), uint256(0x197ca4070a700fc8e818d7d6b1f5aedcef813f1ce25e79672e581dc39850900e));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x226f54b49e5259e709d9c12626816da1606913706f42c67a587f20f3ff2ad34c), uint256(0x07898cb47f0376681c9a82ce389b7904bef416bbddc7acf2141593acd84a2192));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0dccaed560479d4a484150cd13d3868926cd984dbdd694539b6662f3ce552e2d), uint256(0x04414ec92011fdcb41f7c8699b59a395d7a3b5e2acf987d7dd5cbcaf38e5f0d1));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1c5434f8178bd8cfb297ab6629aff1ffa2bcbe9aa655e18a496261c9ebfecf4e), uint256(0x2fbf3ab42ec499368712e054fba7c3d9dad026d7f9aac9ac1b1718e4ad43337a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0a0be067f9e9fa5ce43fa104fce2c851fc6d9e7c2633c28afe3d8ff65c563daa), uint256(0x068b27c853df9f304e6c96d40a9b709f90e35ca550080382be34337579d4557f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0d6eeee589249fd4f697d9d17a284de025f4240daffb3953c77d0785aeb07f7f), uint256(0x0c7f6629f0cb62ceda733be588263b1bcea28177c6d6b6dc45d69ce5a499d43e));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x089307e70d3c4db30180ca2cdefdfd88f5007dc0ead37a4a65bd3ce104be7957), uint256(0x2f63e687df79df40273ff429fa3e319d5b43465cd0782509408f83728cd5fd01));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x141b864a40aadde75c821492cb7582fef2987a7003713c57547c37fbf1a41c46), uint256(0x03dffb8843b2497e84376fed9d13b0c86c800ff6544ddb58ccedd6b73c9766c8));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x13e656b59260e276c14104db9ff9c3a5c91faa4527d0017401a2a282d312c123), uint256(0x14cdc321cecb5a5c0fe7d3b27b54b6af047959abc723d718a87a9388bc46688a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x06e2f3e71bd2deb6bf504b5a8a814b3cafbb724ca534e26ce1587f448c4bca21), uint256(0x004fcbc680c0f4c9c01713ac6d0a64aeba7dc3b6fd933fe3b5a994b4758fa267));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1c929e83e1bb6f169678f6e2f192c0adf4ef3f3eb73c718b225d740663984570), uint256(0x079d4c24dd40ffe714f5683d1df259d5abc5111746c4076683a880bcc953430a));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x28ad0eff96c4b07b5960b2eef75e0f1b7c20615e7ef148b8efd16fcfa34ae2fb), uint256(0x15fddbd426a2894ad90f3ea79af7c897509755cb7cf2fcd09094c2a7a0660a2f));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2a9225b7fbdcef30682f75381e2f89aec695ab79445883d41b677c9bd6bf763d), uint256(0x0e6a3abda8a2ee8a4542838862b196da08b05bea3cb625dcee34b0a475e7ef01));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0b70671fe6f5153fb94d77a830051479bcd0dd7f65555c04ee39a90944a31594), uint256(0x17a1d6b1f7b15efe8db256653216f3ae7fb5792bfb34fcb47c7a6eb8ac5dcf68));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x27cb7c7807c499835865a7bd944248462ba75f9d48184349004c2330b80b5fad), uint256(0x270c71dad3c66ff2491154039351180061906a29920bd81b56909606295f3695));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x113742efdaa93e8a8e9c5cea89a60de84c6dfa3e26e910530cd55ecfb60e1a06), uint256(0x119514fe3444565b9ae227750ded3bb36d28ea4519385bae884abaffda975df9));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0a2a16f2b9ff359f22a89bbfda99fb9b05874ff51e58413eec6fd0d00322bfe1), uint256(0x278462f0331e98bc0d0b9dc396c5ad37722cdf424f8f45a0fafd012bfc9e1700));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2c67bfb6f6374ae5eb4ad7b907d310c30e5f6b52960c5910bce332bbffb03090), uint256(0x09f105a853b6b9d1d7ff97b8c43524832b8e13ba34f3a7a433b920f2272b104e));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x13eb58ff14d885fbde6d9aad6d470b7c5d0282fb51b0e6b66c45f43d1643b0d0), uint256(0x2cb9a94ca3c84a68c81a11f289123fc9ef8f76bc3485a918fde6e7b718be06d7));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x00a223edc380fde12441518c78113901ac417dc04d0a1f2904bd080ec3a405e6), uint256(0x1644bed2281e027e11aadfac53185142cf15ce5988a4a8ad7673ebf87eb2383d));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x27d6fd46502ee9c94c98404d64ff7ec037e7d8378e73da0c43b8e233b68d5f7f), uint256(0x2f7e83a57dde5f21d2d63bf5e26734e42c166f7cccea6062e5f0bc5e9a0e2b19));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x225b9bd99770870ee0feec78f16c8b9102778d12db1c86f0e542bb9cfc145d04), uint256(0x0a90e0bd0958dc0fc4d52f2ba6ea16bf3918f14d4cdd820752b934f9218aeb07));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2f334cf1c6066372f636f8e97c913c15cce23e1781b9189c2927ccdba40e6b74), uint256(0x2fed437ca6868c81c1b242da753c5e150e1fb2e584a6461f81381f8150f0eb48));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1162de7cdc29271dc4fdd9efae86929bc2258ae13bc47cfd649cad0c80ae7150), uint256(0x1fcbf1dc2bcf76b13dda18b7f00072bf0ccbc3a860daa903725458007212d685));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x10f1c11af52fd0429c0a766ada0029f8ea3939021a51bdc54daeea0c521f90a1), uint256(0x19a5e4a03844749bbd0959913fe587b866ea9e8555fc9b6c98c6ac36a99b5874));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x117ca6d182ff46664921904b59679fb2243ed859c9c1e9c23db30280821d548c), uint256(0x305642771665161de3d6caa83462a7efb417ba189452d3a24a65a5ee156aa968));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0d84b050bb0224c7bc4f31b2b42ff1d63c42ca428b07f9f6f3cfa8256cd5a17d), uint256(0x174d080599bd797dc46ed7fd3a061bcf2956c0876fcd7e91feaab7212b33cf0f));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x29a8e3a1c78c38fa352a4a59c532757d108e3827d8ac828ba635da0d65a23366), uint256(0x025b3438ab732a14bfe45e31ee611cf53c03bcabfb680694c413558b8639cf72));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2ccbbb819467347e18448eb1aa89194777a4fbf80ec3936948515c176522e96d), uint256(0x1e412a1ed943d55c4c5b31883ddb431619703381fb1676534c8df2faf90c8793));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1a79454ecaefa7364a1f20375231bda2b8c732aa96c6a0be7dd2bf51a2b2781c), uint256(0x032f0e2ae7b2745560ff8022a34a9bba55ae43fc1e69a91b64ca8f21906d890a));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2f764033a45d2d56a652c8039f509551112529393a8905d7f5484920aa6aed30), uint256(0x0e6123e5fd109185337c1931c9eed320f4916e02ec176071ea503211d4ebd3d0));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1c12e3d21d58c47f43ba3eb1209382afac21a984bad14bad2581f2ed4869fd90), uint256(0x062beb8e3e564229ef358ca20810825e9a435ed20ca8b755a9e2ef620a01a63c));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x20afc12cff86e79b696318b4f721c9fd9a0458b3c4b312e0485a5fdb318612f2), uint256(0x0f6ffa7def2aeefad6af58bce7193633cda1e15c5827af4460a9cae3ee7ad9f1));
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
