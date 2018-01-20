package scroogecoin;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;

import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Created by xinszhou on 11/01/2017.
 * https://github.com/sangszhou/JavaPlayGround
 */
public class TxHandlerTest {

    private static final String SHA_256_WITH_RSA = "SHA256withRSA";  // Same Algorithm as assign1.Crypto.java

    private static final Random RANDOM = new Random();

    private static final int NUM_PEOPLE = 20; // nPeople
    private static final int NUM_UTXO_TRANSACTIONS = 20; // nUTXOTx
    private static final int MAX_UTXO_TRANSACTIONS_OUTPUT = 20; // maxUTXOTxOutput
    private static final double MAX_VALUE = 20; // maxValue
    private static final int NUM_TRANSACTIONS_PER_TEST = 50; // nTxPerTest
    private static final int MAX_INPUT = 20; // maxInput
    private static final int MAX_OUTPUT = 20; // maxOutput
    private static final double PERCENTAGE_CORRUPT = 0.5; // pCorrupt

    private List<KeyPair> people;
    private HashMap<UTXO, KeyPair> utxoToKeyPair;
    private UTXOPool utxoPool;
    private ArrayList<UTXO> utxoSet;
    private int maxValidInput;

    @BeforeEach
    public void setup() throws Exception {
        people = generatePeople(NUM_PEOPLE);

        HashMap<Integer, KeyPair> keyPairAtIndex = new HashMap<>();
        utxoToKeyPair = new HashMap<>();
        utxoPool = new UTXOPool();

        for (int i = 0; i < NUM_UTXO_TRANSACTIONS; i++) {

            int num = RANDOM.nextInt(MAX_UTXO_TRANSACTIONS_OUTPUT) + 1;
            Transaction tx = new Transaction();

            for (int j = 0; j < num; j++) {
                // pick a random public address
                int rIndex = RANDOM.nextInt(people.size());
                PublicKey addr = people.get(rIndex).getPublic();
                double value = RANDOM.nextDouble() * MAX_VALUE;
                tx.addOutput(value, addr);
                keyPairAtIndex.put(j, people.get(rIndex));
            }

            tx.finalize();

            // add all tx outputs to utxo pool
            for (int j = 0; j < num; j++) {
                UTXO ut = new UTXO(tx.getHash(), j);
                utxoPool.addUTXO(ut, tx.getOutput(j));
                utxoToKeyPair.put(ut, keyPairAtIndex.get(j));
            }
        }

        utxoSet = utxoPool.getAllUTXO();
        maxValidInput = Math.min(MAX_INPUT, utxoSet.size());
    }

    @Test
    public void test1() throws Exception {
        //System.out.println("Test 1: test isValidTx() with valid transactions");
        TxHandler txHandler = new TxHandler(new UTXOPool(utxoPool));

        for (int i = 0; i < NUM_TRANSACTIONS_PER_TEST; i++) {
            Transaction tx = new Transaction();
            HashMap<Integer, UTXO> utxoAtIndex = new HashMap<>();
            HashSet<UTXO> utxosSeen = new HashSet<>();

            int nInput = RANDOM.nextInt(maxValidInput) + 1;
            int nOutput = RANDOM.nextInt(MAX_OUTPUT) + 1;

            double inputValue = 0;

            for (int j = 0; j < nInput; j++) {
                UTXO utxo = utxoSet.get(RANDOM.nextInt(utxoSet.size()));
                if (!utxosSeen.add(utxo)) {
                    j--;
                    continue;
                }
                tx.addInput(utxo.getTxHash(), utxo.getIndex());
                inputValue += utxoPool.getTxOutput(utxo).value;
                utxoAtIndex.put(j, utxo);
            }

            // Add Outputs
            double outputValue = 0;
            for (int j = 0; j < nOutput; j++) {
                double value = RANDOM.nextDouble() * MAX_VALUE;
                if (outputValue + value > inputValue) {
                    break;
                }
                int rIndex = RANDOM.nextInt(people.size());
                PublicKey key = people.get(rIndex).getPublic();
                tx.addOutput(value, key);
                outputValue += value;
            }

            // Add Inputs
            for (int j = 0; j < nInput; j++) {
                PrivateKey privateKey = utxoToKeyPair.get(utxoAtIndex.get(j)).getPrivate();
                byte[] signature = sign(privateKey, tx.getRawDataToSign(j));
                tx.addSignature(signature, j);
            }
            tx.finalize();

            Assert.assertTrue(txHandler.isValidTx(tx));
        }
    }

    @Test
    public void test2() throws Exception {
    	//  System.out.println("Test 2: test isValidTx() with transactions containing signatures of incorrect data");
        TxHandler txHandler = new TxHandler(new UTXOPool(utxoPool));

        for (int i = 0; i < NUM_TRANSACTIONS_PER_TEST; i++) {
            Transaction tx = new Transaction();
            boolean uncorrupted = true;
            HashMap<Integer, UTXO> utxoAtIndex = new HashMap<>();
            HashSet<UTXO> utxosSeen = new HashSet<>();
            int nInput = RANDOM.nextInt(maxValidInput) + 1;
            double inputValue = 0;
            for (int j = 0; j < nInput; j++) {
                UTXO utxo = utxoSet.get(RANDOM.nextInt(utxoSet.size()));
                if (!utxosSeen.add(utxo)) {
                    j--;
                    continue;
                }
                tx.addInput(utxo.getTxHash(), utxo.getIndex());
                inputValue += utxoPool.getTxOutput(utxo).value;
                utxoAtIndex.put(j, utxo);
            }
            int nOutput = RANDOM.nextInt(MAX_OUTPUT) + 1;
            double outputValue = 0;
            for (int j = 0; j < nOutput; j++) {
                double value = RANDOM.nextDouble() * MAX_VALUE;
                if (outputValue + value > inputValue)
                    break;
                int rIndex = RANDOM.nextInt(people.size());
                PublicKey addr = people.get(rIndex).getPublic();
                tx.addOutput(value, addr);
                outputValue += value;
            }
            for (int j = 0; j < nInput; j++) {
                byte[] rawData = tx.getRawDataToSign(j);
                if (Math.random() < PERCENTAGE_CORRUPT) {
                    rawData[0]++;
                    uncorrupted = false;
                }
                tx.addSignature(sign(utxoToKeyPair.get(utxoAtIndex.get(j)).getPrivate(), rawData), j);
            }
            tx.finalize();
            if (txHandler.isValidTx(tx) != uncorrupted) {
                Assert.fail();
            }
        }
    }

    @Test
    public void test3() throws Exception {
        // System.out.println("Test 3: test isValidTx() with transactions containing signatures using incorrect private keys");
        TxHandler txHandler = new TxHandler(new UTXOPool(utxoPool));
        for (int i = 0; i < NUM_TRANSACTIONS_PER_TEST; i++) {
            Transaction tx = new Transaction();
            boolean uncorrupted = true;
            HashMap<Integer, UTXO> utxoAtIndex = new HashMap<>();
            HashSet<UTXO> utxosSeen = new HashSet<>();
            int nInput = RANDOM.nextInt(maxValidInput - 1) + 2;
            double inputValue = 0;
            for (int j = 0; j < nInput; j++) {
                UTXO utxo = utxoSet.get(RANDOM.nextInt(utxoSet.size()));
                if (!utxosSeen.add(utxo)) {
                    j--;
                    continue;
                }
                tx.addInput(utxo.getTxHash(), utxo.getIndex());
                inputValue += utxoPool.getTxOutput(utxo).value;
                utxoAtIndex.put(j, utxo);
            }
            int nOutput = RANDOM.nextInt(MAX_OUTPUT) + 1;
            double outputValue = 0;
            for (int j = 0; j < nOutput; j++) {
                double value = RANDOM.nextDouble() * MAX_VALUE;
                if (outputValue + value > inputValue)
                    break;
                int rIndex = RANDOM.nextInt(people.size());
                PublicKey addr = people.get(rIndex).getPublic();
                tx.addOutput(value, addr);
                outputValue += value;
            }
            for (int j = 0; j < nInput; j++) {
                KeyPair keyPair = utxoToKeyPair.get(utxoAtIndex.get(j));
                if (Math.random() < PERCENTAGE_CORRUPT) {
                    int index = people.indexOf(keyPair);
                    keyPair = people.get((index + 1) % NUM_PEOPLE);
                    uncorrupted = false;
                }
                tx.addSignature(sign(keyPair.getPrivate(), tx.getRawDataToSign(j)), j);
            }
            tx.finalize();
            if (txHandler.isValidTx(tx) != uncorrupted) {
                Assert.fail();
            }
        }
    }

    private byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(SHA_256_WITH_RSA);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    private ArrayList<KeyPair> generatePeople(int number) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        ArrayList<KeyPair> result = new ArrayList<>(number);
        for (int i = 0; i < number; i++) {
            result.add(keyGen.genKeyPair());
        }
        return result;
    }
}