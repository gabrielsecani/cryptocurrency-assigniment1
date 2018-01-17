package scroogecoin;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.IntStream;

public class TxHandler {

	private UTXOPool pool;

	/**
	 * Creates a public ledger whose current UTXOPool (collection of unspent
	 * transaction outputs) is {@code utxoPool}. This should make a copy of utxoPool
	 * by using the UTXOPool(UTXOPool uPool) constructor.
	 */
	public TxHandler(UTXOPool utxoPool) {
		// IMPLEMENT THIS
		this.pool = new UTXOPool(utxoPool);
	}

	/**
	 * @return true if: (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
	 *         (2) the signatures on each input of {@code tx} are valid,
	 *         (3) no UTXO is claimed multiple times by {@code tx},
	 *         (4) all of {@code tx}s output values are non-negative, and 
	 *         (5) the sum of {@code tx}s input values is greater than or equal to the sum of its
	 *         output values; and false otherwise.
	 */
	public boolean isValidTx(Transaction tx) {
		// IMPLEMENT THIS
		
        // used {@code Transaction.Output}
		Set<UTXO> usedUTXOs = new HashSet<>();

		return IntStream.range(0, tx.numInputs())
				.allMatch(i -> {
		        	// one input needs one output from pool, so get it.
		            Transaction.Input in = tx.getInput(i);
		            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
		            Transaction.Output output = pool.getTxOutput(utxo);
		            // (1) all outputs claimed by {@code tx} are in the current UTXO pool,
		            if (output == null)
		            	return false;
		
		            // (3) no UTXO is claimed multiple times by {@code tx},
		            if (usedUTXOs.contains(utxo))
		            	return false;
		            
		            // (2) the signatures on each input of {@code tx} are valid,
		            if (! Crypto.verifySignature(/*pubKey*/output.address, /*message*/tx.getRawDataToSign(i), /*input signature*/in.signature))
						return false;
		 
		            usedUTXOs.add(utxo);
		            return true;
		        })
				&& allOutputValuesAreNonNegative(tx)
				&& inputValuesGreaterThanOrEqualToOutput(tx);
	}
	
	/**
	 * All output values are non negative
	 * @param tx
	 * @return boolean
	 */
	private boolean allOutputValuesAreNonNegative(Transaction tx) {
		return tx.getOutputs().stream().allMatch(o -> o.value >= 0);
	}

	/**
	 * Check every tx for sum of inputs is greater than or equal outputs.
	 * 
	 * @param tx
	 * @return boolean
	 */
	private boolean inputValuesGreaterThanOrEqualToOutput(Transaction tx) {
		double inps = tx.getInputs().stream().mapToDouble(inx -> tx.getOutput(inx.outputIndex).value).sum();
		double outs = tx.getOutputs().stream().mapToDouble(outx -> outx.value).sum();
		return inps >= outs;
	}

	/**
	 * Handles each epoch by receiving an unordered array of proposed transactions,
	 * checking each transaction for correctness, returning a mutually valid array
	 * of accepted transactions, and updating the current UTXO pool as appropriate.
	 */
	public Transaction[] handleTxs(Transaction[] possibleTxs) {
		// IMPLEMENT THIS
		return Arrays.stream(possibleTxs)
                .filter( tx -> isValidTx(tx))
                .peek(this::updatePool)
                .toArray(Transaction[]::new);
    }
    
    private void updatePool(Transaction tx) {
        //remove all new inputs from pool that are on a valid transaction
        tx.getInputs().forEach(inp -> pool.removeUTXO(new UTXO(inp.prevTxHash, inp.outputIndex)));

        //add all outputs to the pool
        IntStream.range(0, tx.numOutputs())
                .forEach(idx -> pool.addUTXO(new UTXO(tx.getHash(), idx), tx.getOutput(idx)));
        
    }

}
