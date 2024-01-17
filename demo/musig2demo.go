package main

import "C"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"log"
	"math/big"

	"github.com/chainx-org/bitcoin-go-api/musig2"
)

func createAddress(publicKeyList []string, threshold uint8) {
	//pubkey0 := "042f7e2f0f3e912bf416234913b388393beb5092418fea986e45c0b9633adefd85168f3b1d13ae29651c29e424760b3795fc78152ac119e0dc4e2b9055329099b3"
	//pubkey1 := "04a09e8182977710bab64472c0ecaf9e52255a890554a00a62facd05c0b13817f8995bf590851c19914bfc939d53365b90cc2f0fcfddaca184f0c1e7ce1736f0b8"
	//pubkey2 := "0451e0dc3d9709d860c49785fc84b62909d991cffd81592f6994c452438f91b6a2e586541c4b3bc1ebeb5fb9fad2ed2e696b2175c54458ab6f103717cbeeb4e52c"
	// Generate threshold signature address
	thresholdPubkey, err := musig2.GenerateThresholdPubkey(publicKeyList, threshold)
	if err != nil {
		log.Fatal(err)
	}
	thresholdAddress, err := musig2.GetMyAddress(thresholdPubkey, "testnet")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Threshold Address: ", thresholdAddress)
}

func sign(privateKeyList []string, totalPublicKey []string) {

	var publicKeyList []string
	for _, privateKey := range privateKeyList {
		pubkey, err := musig2.GetMyPubkey(privateKey)
		if err != nil {
			log.Fatal(err)
		}
		println("pubkey ", pubkey)
		publicKeyList = append(publicKeyList, pubkey)
	}

	// input:
	prevTxs := []string{"02000000000102b3c060d488e9ab29ac295b81f47c9360d4abec9e4903c65d3806855640fcf7710000000000000000005b39603487e5e645eeae76616d886c98c7039169d32651af48574038fa747f730100000000000000000222020000000000002251204e0f35035f0b223dd1b8751bd0a3648063a6ab84c9d9bac18fbd0cc8aa557fb4231206000000000022512035aa4d36f01380d58871bd061089b5345518bb3cacfdc1f2be3aea710239b65a0340623308634a4b456ad53c64d331fa3dd243ba2ce4800bab8cd374ad5be97d08d5925b6c5a7df2e216aa692649f3c9f5dd9db0801ad9f7c0ac4558da48b3a8683d22205b52dd1c5abac34b424588ef853a6e2a9f9f71d6303f7bcd2924355ec0e6bbe9ac81c19c6472ef499bff9f31ee120eedd5a3252cc002b144cb5b96f13f5972deca133ea61d79e91eee40c5bb33fcfef1c9d8c11208898f8386984fc14435a8716c8ab025e385236835873f84e725d3d55cde9ca5229d07158767a7c2bb6cd23e7ee262678e72f618767d2199b5f3d6376cf12292f65423931abed821e0fc4683406cf10340af49a0cc0e3af1612657c97ab20e74ec8f82862a8fd7c64ee51a376a25f58578a24cd6a38a11fb5edd43b186b6619ca16a37a02504bb30ca98a2702e0d5512cc22205b52dd1c5abac34b424588ef853a6e2a9f9f71d6303f7bcd2924355ec0e6bbe9ac81c19c6472ef499bff9f31ee120eedd5a3252cc002b144cb5b96f13f5972deca133ea61d79e91eee40c5bb33fcfef1c9d8c11208898f8386984fc14435a8716c8ab025e385236835873f84e725d3d55cde9ca5229d07158767a7c2bb6cd23e7ee262678e72f618767d2199b5f3d6376cf12292f65423931abed821e0fc4683406cf100000000"}
	txids := []string{"8ea30542a37f14076b44ec1085bd5bb6581aef09b19ed4b3b471bbefe1aaaf99"}
	// index of unspent output in prevTxs
	inputIndexs := []uint32{1}
	// output:
	addresses := []string{"tb1pzphxzagk0tlpzkwkdze9kcy3rq56wrt0aa4ytsftxlecpd08agkspx5mvh", "tb1pxk4y6dhszwqdtzr3h5rppzd4x3233weu4n7uru478t48zq3ekedqqyw5m7"}
	amounts := []uint64{697, 396952}
	// 1. Construct an unsigned transaction, containing all transaction information except the signature
	baseTx, err := musig2.GenerateRawTx(prevTxs, txids, inputIndexs, addresses, amounts)
	if err != nil {
		log.Fatal(err)
	}
	// unsigned raw tx for check on chain
	unsignedTx, err := musig2.GetUnsignedTx(baseTx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Unsigned Tx: ", unsignedTx)
	log.Println("base Tx: ", baseTx)

	var thresholdTx string
	for i := 0; i < len(txids); i++ {
		// 2. Calculate the aggregated public key of the signers
		pubkeyBC, err := musig2.GetAggPublicKey(publicKeyList)
		if err != nil {
			log.Fatal(err)
		}
		// 3. Calculate sighash for one input
		sighash, err := musig2.GetSighash(baseTx, txids[i], inputIndexs[i], pubkeyBC, 1)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Sighash: ", sighash)
		log.Println("pubkeyBC: ", pubkeyBC)

		round2MsgList, _ := musig2.GetSignMessage(privateKeyList, publicKeyList, sighash)

		// 7. Collect second round of messages from all current signers to generate signatures
		multiSignature, err := musig2.GetAggSignature(round2MsgList)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("MultiSignature: ", multiSignature)
		//multiSignature = "a28a7b25e575727b8aafbb1e5b9dad3778ef0a2d0ed5b092e90447d7c05f9853976f1470b1e64b5b2ea60c3fda3da933995dd5198c589f5116edd1a5f24362a7"
		// 8. Based on all signer public keys and the aggregated public keys of
		//    the people who are signing to generate signature auxiliary information
		controlBlock, err := musig2.GenerateControlBlock(totalPublicKey, uint8(len(privateKeyList)), pubkeyBC)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Control Block: ", controlBlock)
		// 9. Put signature into the transaction
		thresholdTx, err = musig2.BuildThresholdTx(baseTx, multiSignature, pubkeyBC, controlBlock, txids[i], inputIndexs[i])
		if err != nil {
			log.Fatal(err)
		}
		//log.Println("Current Threshold Tx: ", thresholdTx)
	}
	// 10. When all inputs have been signed, the transaction is constructed
	log.Println("Final Threshold Tx: ", thresholdTx)
}

func newKeyPair(count int) {
	var privateKeyList string
	var publicKeyList string
	for index := 0; index < count; index++ {
		curve := elliptic.P256()
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Panic(err)
		}
		privateKey := private.D.Bytes()
		//private.PublicKey
		pubKey, err := musig2.GetMyPubkey(hex.EncodeToString(privateKey))
		privateKeyList = privateKeyList + "\"" + hex.EncodeToString(privateKey) + "\","
		publicKeyList = publicKeyList + "\"" + pubKey + "\","
		println("private key ", hex.EncodeToString(privateKey), "public key ", pubKey)
	}
	println("private key ", privateKeyList)
	println("public key ", publicKeyList)
}
func main() {

	round2MsgList := []string{"04c61088c02c4e5da1265764c19f65a280a70028fcf4318ef98fa9c7f87e8ace8b7d10f12ca4fe4e4e23c7f351ed27423d657ff18ad95061f2a9a5f2922ab1188574200097be43aad8f1e2e215513e9c5445e628bb0e602b0dc2b2961de3e43ec6", "0453b6d00c43735380c25e2a9af6dda7ed40cc7ed4e325e367fadace2095cedc80588a009484aea101281574ccf8c8d0f53e8b2a63707bed41453656f5eb4d7306393f8107c6a382a688e21be6a3057aaa31970ec06e044ff8046616fdc726f333"}
	multiSignature, _ := musig2.GetAggSignature(round2MsgList)
	println("xxx", multiSignature)
	threshold := uint8(2)
	totalKey := int64(4)
	newKeyPair(int(totalKey))
	privateKeyList := []string{"d8eb2dc5e470042dc4b1105ede5d85291ed05d42f5064de9e2013014eb65786e", "b647a92cec286a301fbe860089464d0c55f630e9b13a44ca6b4a56520ad63a8c", "f6c8e29d148658b2ce5214c42a1b69c3decd8b3f872aed2af627ac04841b9dc5", "42062aec1100f8be630bbc3357a7fef862ef0612f715e412a46e505ccef5553c"}
	publicKeyList := []string{"0410020ee255c91a6e6cb972b85105cab95e849d594475c6ec4820e15bda99bb60769b07c484c0d4c155081a47164d1bcbfe7b28b21e7f27af3b5fffd2737eb6a5", "0469f239a1afa8ad48a43a39424565b55302f2de64093298477743d78ae48beab62767ae59c0defd4778e7119629e411b2506bd5824013aa2d6a8103685618dda3", "043e8fe95c72b7e5f1ae5e3112e7e7d2df4e6206291434006fb99708903b77d0de51497e320c98abf11026ca5efbf8bf03e46552c5a5352f624dfe54a05d02a3d0", "047ef66a6e6d82960a1ca4b30d23ec4958c6793a3e3acd96aac55c93bc855d4c55be1bb6a7a0cfe42b759e085e0adcf8efcc1650e93eaf785cec764e9b0f58956d"}
	createAddress(publicKeyList, threshold)
	//
	var signPrivateKeyList []string
	indexList := roundArr(threshold, totalKey)
	indexList = []int64{1, 2}
	for _, index := range indexList {
		signPrivateKeyList = append(signPrivateKeyList, privateKeyList[index])
	}

	println("signPrivateKeyList", len(signPrivateKeyList))

	sign(signPrivateKeyList, publicKeyList)
	//old()
}

func roundArr(threshold uint8, totalKey int64) []int64 {
	var arr []int64
	for i := uint8(0); i < threshold; i++ {
		rand := round(totalKey, arr)
		arr = append(arr, rand)
	}
	return arr
}
func round(max int64, arr []int64) int64 {
	for i := 0; i >= 0; i++ {
		rand, _ := rand.Int(rand.Reader, big.NewInt(max)) //生成0-99之间的随机数
		if !in(rand.Int64(), arr) {
			return rand.Int64()
		}
	}
	return 0
}

func in(target int64, str_array []int64) bool {
	for _, element := range str_array {
		if target == element {
			return true
		}
	}
	return false
}

func old() {
	log.SetFlags(log.Llongfile | log.Lmicroseconds | log.Ldate)
	log.SetPrefix("[Bitcoin-Taproot]")
	// Generate non-threshold signature address
	PHRASE0 := "flame flock chunk trim modify raise rough client coin busy income smile"
	private0, err := musig2.GetMyPrivkey(PHRASE0, "")
	if err != nil {
		log.Fatal(err)
	}
	pubkey0, err := musig2.GetMyPubkey(private0)
	if err != nil {
		log.Fatal(err)
	}
	address0, err := musig2.GetMyAddress(pubkey0, "signet")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("address0: ", address0)

	PHRASE1 := "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics"
	private1, err := musig2.GetMyPrivkey(PHRASE1, "")
	if err != nil {
		log.Fatal(err)
	}
	pubkey1, err := musig2.GetMyPubkey(private1)
	if err != nil {
		log.Fatal(err)
	}

	PHRASE2 := "awesome beef hill broccoli strike poem rebel unique turn circle cool system"
	private2, err := musig2.GetMyPrivkey(PHRASE2, "")
	if err != nil {
		log.Fatal(err)
	}
	pubkey2, err := musig2.GetMyPubkey(private2)
	if err != nil {
		log.Fatal(err)
	}

	// Cost of non-threshold signature addresses
	// input:
	prevTxs := []string{"020000000001014be640313b023c3c731b7e89c3f97bebcebf9772ea2f7747e5604f4483a447b601000000000000000002a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bbc027090000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01404dc68b31efc1468f84db7e9716a84c19bbc53c2d252fd1d72fa6469e860a74486b0990332b69718dbcb5acad9d48634d23ee9c215ab15fb16f4732bed1770fdf00000000"}
	txids := []string{"1f8e0f7dfa37b184244d022cdf2bc7b8e0bac8b52143ea786fa3f7bbe049eeae"}
	// index of unspent output in prevTxs
	inputIndexs := []uint32{1}
	// output:
	addresses := []string{"tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw", "35516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38", "tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68"}
	amounts := []uint64{100000, 0, 400000}
	// unsigned tx:
	// 1. Construct an unsigned transaction, containing all transaction information except the signature
	baseTx, err := musig2.GenerateRawTx(prevTxs, txids, inputIndexs, addresses, amounts)
	if err != nil {
		log.Fatal(err)
	}
	// unsigned raw tx for check on chain
	unsignedTx, err := musig2.GetUnsignedTx(baseTx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Unsigned Tx: ", unsignedTx)
	var taprootTx string
	for i := 0; i < len(txids); i++ {
		privkey := "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40"
		// 2. Calculate input sighash for one input
		sighash, err := musig2.GetSighash(baseTx, txids[i], inputIndexs[i], "", 0)
		log.Println("Sighash: ", sighash)
		if err != nil {
			log.Fatal(err)
		}
		// 3. Calculate signature for one input
		schnorrSignature, err := musig2.GenerateSchnorrSignature(sighash, privkey)
		log.Println("SchnorrSignature: ", schnorrSignature)
		if err != nil {
			log.Fatal(err)
		}
		// 4. Put signature into unsigned tx
		taprootTx, err = musig2.BuildTaprootTx(baseTx, schnorrSignature, txids[i], inputIndexs[i])
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Current Taproot Tx: ", taprootTx)
	}
	// 5. When all inputs have been signed, the transaction is constructed
	log.Println("Final Taproot Tx: ", taprootTx)

	// Generate threshold signature address
	log.Println("Pubkey 0", private0, "pubkye 1", pubkey1, "pubkey 2", pubkey2)
	log.Println("private0 0", private0, "private 1", private1, "private 2", private2)
	thresholdPubkey, err := musig2.GenerateThresholdPubkey([]string{pubkey0, pubkey1, pubkey2}, 2)
	if err != nil {
		log.Fatal(err)
	}
	thresholdAddress, err := musig2.GetMyAddress(thresholdPubkey, "signet")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Threshold Address: ", thresholdAddress)

	// Cost of threshold signature address
	privateA := "e5bb018d70c6fb5dd8ad91f6c88fb0e6fdab2c482978c95bb3794ca6e2e50dc2"
	privateB := "a7150e8f24ab26ebebddd831aeb8f00ecb593df3b80ae1e8b8be01351805f2d6"
	privateC := "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40"
	pubkeyA, err := musig2.GetMyPubkey(privateA)
	if err != nil {
		log.Fatal(err)
	}
	pubkeyB, err := musig2.GetMyPubkey(privateB)
	if err != nil {
		log.Fatal(err)
	}
	pubkeyC, err := musig2.GetMyPubkey(privateC)
	if err != nil {
		log.Fatal(err)
	}

	// input:
	prevTxs = []string{"02000000000101aeee49e0bbf7a36f78ea4321b5c8bae0b8c72bdf2c024d2484b137fa7d0f8e1f01000000000000000003a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bb0000000000000000326a3035516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38801a060000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01409e325889515ed47099fdd7098e6fafdc880b21456d3f368457de923f4229286e34cef68816348a0581ae5885ede248a35ac4b09da61a7b9b90f34c200872d2e300000000"}
	txids = []string{"8e5d37c768acc4f3e794a10ad27bf0256237c80c22fa67117e3e3e1aec22ea5f"}
	// index of unspent output in prevTxs
	inputIndexs = []uint32{0}
	// output:
	addresses = []string{"tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68", "tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw"}
	amounts = []uint64{50000, 40000}
	// 1. Construct an unsigned transaction, containing all transaction information except the signature
	baseTx, err = musig2.GenerateRawTx(prevTxs, txids, inputIndexs, addresses, amounts)
	if err != nil {
		log.Fatal(err)
	}
	// unsigned raw tx for check on chain
	unsignedTx, err = musig2.GetUnsignedTx(baseTx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Unsigned Tx: ", unsignedTx)

	var thresholdTx string
	for i := 0; i < len(txids); i++ {
		// 2. Calculate the aggregated public key of the signers
		pubkeyBC, err := musig2.GetAggPublicKey([]string{pubkeyB, pubkeyC})
		if err != nil {
			log.Fatal(err)
		}
		// 3. Calculate sighash for one input
		sighash, err := musig2.GetSighash(baseTx, txids[i], inputIndexs[i], pubkeyBC, 1)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Sighash: ", sighash)
		// start musig2 communication
		// 4. Get your own state
		round1State0 := musig2.GetRound1State()
		// encode the state for persistence
		round1State0Encode, err := musig2.EncodeRound1State(round1State0)
		if err != nil {
			log.Fatal(err)
		}
		// decode to the state from persistently store
		round1State0 = musig2.DecodeRound1State(round1State0Encode)
		round1State1 := musig2.GetRound1State()
		// 5. Get your own first round of messages
		round1Msg0, err := musig2.GetRound1Msg(round1State0)
		if err != nil {
			log.Fatal(err)
		}
		round1Msg1, err := musig2.GetRound1Msg(round1State1)
		if err != nil {
			log.Fatal(err)
		}
		// 6. Collect the first round of messages from all current signers to
		//    generate its own second round of messages and broadcast it
		round2Msg0, err := musig2.GetRound2Msg(round1State0, sighash, privateB, []string{pubkeyB, pubkeyC}, []string{round1Msg1})
		if err != nil {
			log.Fatal(err)
		}
		round2Msg1, err := musig2.GetRound2Msg(round1State1, sighash, privateC, []string{pubkeyB, pubkeyC}, []string{round1Msg0})
		if err != nil {
			log.Fatal(err)
		}
		// 7. Collect second round of messages from all current signers to generate signatures
		multiSignature, err := musig2.GetAggSignature([]string{round2Msg0, round2Msg1})
		if err != nil {
			log.Fatal(err)
		}

		log.Println("MultiSignature: ", multiSignature)
		// 8. Based on all signer public keys and the aggregated public keys of
		//    the people who are signing to generate signature auxiliary information
		controlBlock, err := musig2.GenerateControlBlock([]string{pubkeyA, pubkeyB, pubkeyC}, 2, pubkeyBC)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Control Block: ", controlBlock)
		// 9. Put signature into the transaction
		thresholdTx, err = musig2.BuildThresholdTx(baseTx, multiSignature, pubkeyBC, controlBlock, txids[i], inputIndexs[i])
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Current Threshold Tx: ", thresholdTx)
	}
	// 10. When all inputs have been signed, the transaction is constructed
	log.Println("Final Threshold Tx: ", thresholdTx)

	// other tool func test
	scriptPubkey, err := musig2.GetScriptPubkey("tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("ScriptPubkey: ", scriptPubkey)
}
