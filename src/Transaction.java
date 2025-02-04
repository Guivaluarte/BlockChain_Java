import java.security.*;
import java.util.ArrayList;

public class Transaction {
    public String transactionId; // this is also the hash of the transaction.
    public PublicKey sender; // senders address/public key.
    public PublicKey reciepient; // Recipients address/public key.
    public float value;
    public byte[] signature; // Create a signature for security

    public ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();
    public ArrayList<TransactionOutput> outputs = new ArrayList<TransactionOutput>();

    public static int sequence = 0;

    public Transaction(PublicKey from, PublicKey to, float value, ArrayList<TransactionInput> inputs){
        this.sender = from;
        this.reciepient = to;
        this.value = value;
        this.inputs = inputs;
    }

    //Calculate transaction Hash

    private String calculateHash(){
        sequence++;
        return HashUtil.applySha256(
                HashUtil.getStringFromKey(sender) +
                        HashUtil.getStringFromKey(reciepient) +
                        Float.toString(value) + sequence
        );
    }

    public void generateSignature(PrivateKey privateKey){
        String data = HashUtil.getStringFromKey(sender)+ HashUtil.getStringFromKey(reciepient) + Float.toString(value);
        signature = HashUtil.applyECDSASig(privateKey,data);

    }

    public boolean verifiySignature() {
        String data = HashUtil.getStringFromKey(sender) + HashUtil.getStringFromKey(reciepient) + Float.toString(value);
        return HashUtil.verifyECDSASig(sender, data, signature);
    }

    public boolean processTransaction(){

        if (verifiySignature() == false){
            System.out.println("#Transaction Signature failed to verify");
            return false;
        }

        //gather transaction inputs (Make sure they are unspent):
        for (TransactionInput i : inputs) {
            i.UTXO = Icoin.UTXOs.get(i.transactionOutputId);
        }

        //check if transaction is valid:
        if(getInputsValue() < Icoin.minimumTransaction) {
            System.out.println("#Transaction Inputs to small: " + getInputsValue());
            return false;
        }

        //generate transaction outputs
        float leftOver = getInputsValue() - value; //get value of inputs then the leftover:
        transactionId = calculateHash();
        outputs.add(new TransactionOutput( this.reciepient, value,transactionId)); //send value to recipient
        outputs.add(new TransactionOutput( this.sender, leftOver,transactionId)); //send the leftover back to sender

        for(TransactionOutput o : outputs) {
            Icoin.UTXOs.put(o.id , o);
        }

        for(TransactionInput i : inputs) {
            if(i.UTXO == null) continue; //if Transaction can't be found skip it
            Icoin.UTXOs.remove(i.UTXO.id);
        }

        return true;
    }

    public float getInputsValue() {
        float total = 0;
        for(TransactionInput i : inputs) {
            if(i.UTXO == null) continue; //if Transaction can't be found skip it
            total += i.UTXO.value;
        }
        return total;
    }

    public float getOutputsValue() {
        float total = 0;
        for(TransactionOutput o : outputs) {
            total += o.value;
        }
        return total;
    }



}
