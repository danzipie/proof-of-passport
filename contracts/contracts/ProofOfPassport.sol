// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {Groth16Verifier} from "./Verifier.sol";
import {Base64} from "./libraries/Base64.sol";
import "hardhat/console.sol";

contract ProofOfPassport is ERC721Enumerable, Ownable {
    using Strings for uint256;
    using Base64 for *;

    Groth16Verifier public immutable verifier;
    address public cscaPubkey = 0x0000000000000000000000000000000000000000;

    mapping(uint256 => bool) public nullifiers;

    struct AttributePosition {
        string name;
        uint256 start;
        uint256 end;
        uint256 index;
    }

    struct Attributes {
        string[7] values;
    }

    AttributePosition[] public attributePositions;

    mapping(uint256 => Attributes) private tokenAttributes;

    constructor(Groth16Verifier v) ERC721("ProofOfPassport", "ProofOfPassport") {
        verifier = v;
        setupAttributes();
        transferOwnership(msg.sender);
    }

    function setupAttributes() internal {
        attributePositions.push(AttributePosition("issuing_state", 2, 4, 0));
        attributePositions.push(AttributePosition("name", 5, 43, 1));
        attributePositions.push(AttributePosition("passport_number", 44, 52, 2));
        attributePositions.push(AttributePosition("nationality", 54, 56, 3));
        attributePositions.push(AttributePosition("date_of_birth", 57, 62, 4));
        attributePositions.push(AttributePosition("gender", 64, 64, 5));
        attributePositions.push(AttributePosition("expiry_date", 65, 70, 6));
    }

    function setCSCApubKey(address _CSCApubKey) public onlyOwner {
        cscaPubkey = _CSCApubKey;
    }

    function mint(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[6] memory inputs
    ) public {
        // Check eth address committed to in proof matches msg.sender, to avoid replayability
        require(address(uint160(inputs[5])) == msg.sender, "Invalid address");
        // check that the nullifier has not been used before
        require(!nullifiers[inputs[3]], "Signature already nullified");

        // Verify that the public key for RSA matches the hardcoded one
        // for (uint256 i = body_len; i < msg_len - 1; i++) {
        //     require(mailServer.isVerified(domain, i - body_len, inputs[i]), "Invalid: RSA modulus not matched");
        // }
        // inputs[4]

        // Verify that the public key for RSA matches the hardcoded one
        // commented out for now, since hard to keep up with all
        // require(cscaPubkey == inputs[], "Invalid pubkey in inputs");

        require(verifier.verifyProof(a, b, c, inputs), "Invalid Proof");

        // Effects: Mint token
        _mint(msg.sender, totalSupply());
        nullifiers[inputs[3]] = true;


        // Set attributes
        uint256[3] memory firstThree = sliceFirstThree(inputs);
        bytes memory charcodes = fieldElementsToBytes(firstThree);
        // console.logBytes1(charcodes[21]);

        Attributes storage attributes = tokenAttributes[totalSupply()];

        for (uint i = 0; i < attributePositions.length; i++) {
            AttributePosition memory attribute = attributePositions[i];
            bytes memory attributeBytes = new bytes(attribute.end - attribute.start + 1);
            for (uint j = attribute.start; j <= attribute.end; j++) {
                attributeBytes[j - attribute.start] = charcodes[j];
            }
            string memory attributeValue = string(attributeBytes);
            console.log(attribute.name, attributeValue);
            attributes.values[i] = attributeValue;
        }
    }

    function fieldElementsToBytes(uint256[3] memory publicSignals) public pure returns (bytes memory) {
        uint8[3] memory bytesCount = [31, 31, 26];
        bytes memory bytesArray = new bytes(88); // 31 + 31 + 26

        uint256 index = 0;
        for (uint256 i = 0; i < 3; i++) {
            uint256 element = publicSignals[i];
            for (uint8 j = 0; j < bytesCount[i]; j++) {
                bytesArray[index++] = bytes1(uint8(element & 0xFF));
                element = element >> 8;
            }
        }

        return bytesArray;
    }

    function sliceFirstThree(uint256[6] memory input) public pure returns (uint256[3] memory) {
        uint256[3] memory sliced;

        for (uint256 i = 0; i < 3; i++) {
            sliced[i] = input[i];
        }

        return sliced;
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId,
        uint256 batchSize
    ) internal virtual override {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
        require(from == address(0), "Cannot transfer - Proof of Passport is soulbound");
    }

    function tokenURI(
        uint256 _tokenId
    ) public view virtual override returns (string memory) {
        require(
            _exists(_tokenId),
            "ERC721Metadata: URI query for nonexistent token"
        );
        Attributes memory attributes = tokenAttributes[_tokenId];
        bytes memory baseURI = (
            abi.encodePacked(
                '{ "attributes": [',
                    '{"trait_type": "Issuing State", "value": "',
                    attributes.values[0],
                    '"},{"trait_type": "Name", "value": "',
                    attributes.values[1],
                    '"},{"trait_type": "Passport Number", "value": "',
                    attributes.values[2],
                    '"},{"trait_type": "Nationality", "value": "',
                    attributes.values[3],
                    '"},{"trait_type": "Date of birth", "value": "',
                    attributes.values[4],
                    '"},{"trait_type": "Gender", "value": "',
                    attributes.values[5],
                    '"},{"trait_type": "Expiry date", "value": "',
                    attributes.values[6],
                    '"},',
                "],",
                '"description": "Proof of Passport guarantees possession of a valid passport.","external_url": "https://github.com/zk-passport/proof-of-passport","image": "https://i.imgur.com/9kvetij.png","name": "Proof of Passport #',
                _tokenId.toString(),
                '"}'
            )
        );

        return
            string(
                abi.encodePacked(
                    "data:application/json;base64,",
                    baseURI.encode()
                )
            );
    }
}